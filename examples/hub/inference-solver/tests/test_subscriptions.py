"""Subscriptions through real HTTP and SQLite: plans, buying from the balance, windows and resets."""
from pathlib import Path
import json
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_service import Flow
from subscriptions import PERIOD, WINDOWS, window

MODEL, OTHER = "test/one", "test/two"


class SubscriptionFlow(Flow):
    def plan(self, name="Pro", price="25", millions="0.001", resets="5h", models=(MODEL,), session=None, **extra):
        return self.call("/api/admin/subscriptions/plan", {"name": name, "price_usd": price, "tokens_millions": millions, "resets": resets,
                                                           "models": list(models), **extra}, session or self.admin)

    def funded(self, dollars=50):
        member = self.member()
        user = self.call("/api/session", session=member)[1]["user"]["id"]
        with self.service.store.db() as db:
            db.execute("INSERT INTO credit_ledger VALUES(?,?,?,'test',?,NULL,NULL)", ("fund-" + user, user, dollars * 1000000, int(time.time())))
        return member, user

    def balance(self, member):
        return self.call("/api/payments", session=member)[1]["balance_microusd"]

    def mine(self, member):
        return self.call("/api/subscriptions", session=member)[1]["subscription"]

    def test_the_administrator_offers_one_to_five_subscriptions_each_with_its_models(self):
        self.endpoint()
        member = self.member()
        self.assertEqual(self.plan(session=member)[0], 403)
        for number in range(5):
            status, state, _ = self.plan(name=f"Plan {number}", price=str(number + 1))
            self.assertEqual(status, 200, state)
        status, refused, _ = self.plan(name="Sixth")
        self.assertEqual(status, 400)
        self.assertIn("at most 5 subscriptions", refused["error"]["message"])
        plans = self.call("/api/admin/subscriptions", session=self.admin)[1]["plans"]
        self.assertEqual([p["name"] for p in plans], [f"Plan {n}" for n in range(5)])
        # Edited in place, and removed to make room.
        edited = next(p for p in self.plan(id=plans[0]["id"], name="Starter", millions="2.5", resets="week", models=(MODEL, OTHER))[1]["plans"]
                      if p["id"] == plans[0]["id"])
        self.assertEqual((edited["name"], edited["token_limit"], edited["resets"], edited["models"]), ("Starter", 2500000, "week", [MODEL, OTHER]))
        self.assertEqual(self.call("/api/admin/subscriptions/remove", {"id": plans[4]["id"]}, self.admin)[0], 200)
        self.assertEqual(self.plan(name="Sixth")[0], 200)
        for bad in ({"resets": "month"}, {"millions": "0"}, {"millions": "1e3"}, {"price": "-1"}, {"name": " "}, {"models": ()}, {"models": ("not/served",)}):
            self.assertEqual(self.plan(**{"name": "Bad", "price": "1", "millions": "1", **bad})[0], 400, bad)
        # Everyone signed in sees the plans offered with their models, but never their tokens.
        offered = self.call("/api/subscriptions", session=member)[1]["plans"]
        self.assertEqual(len(offered), 5)
        self.assertTrue(all("token_limit" not in plan and plan["models"] for plan in offered))

    def test_a_subscription_covers_its_models_until_the_window_is_used_up_then_the_balance_pays(self):
        self.endpoint()
        for model in (MODEL, OTHER):
            self.assertEqual(self.call("/api/admin/prices", {"model": model, "input_usd": "1", "output_usd": "2"}, self.admin)[0], 200)
        plan = self.plan(price="5")[1]["plans"][0]
        member, user = self.funded(10)
        key = self.key(session=member)["key"]
        status, bought, _ = self.call("/api/subscriptions/subscribe", {"plan": plan["id"]}, member)
        self.assertEqual(status, 200, bought)
        self.assertEqual(self.balance(member), 5000000)
        self.assertAlmostEqual(bought["subscription"]["ends"], time.time() + PERIOD, delta=5)

        # Included: nothing is charged, and the fixture's 3 + 2 tokens count in a new 5-hour window.
        # The subscriber sees the share of the limit used, never the tokens.
        self.assertEqual(self.call("/v1/chat/completions", self.completion(MODEL), key=key)[0], 200)
        self.assertEqual(self.balance(member), 5000000)
        mine = self.mine(member)
        self.assertEqual(mine["used_percent"], 0)
        self.assertNotIn("used", mine)
        self.assertNotIn("token_limit", mine)
        self.assertNotIn("0.001", json.dumps(mine))
        self.assertAlmostEqual(mine["resets_at"], time.time() + WINDOWS["5h"], delta=5)
        self.assertEqual(self.call("/api/admin/subscriptions", session=self.admin)[1]["subscribers"][0]["used"], 5)
        latest = self.call("/api/usage", session=member)[1]["requests"][0]
        self.assertEqual((latest["billing_state"], latest["cost_microusd"]), ("subscription", 0))
        # A model outside the plan is charged from the balance ($0.000003 + $0.000004).
        self.assertEqual(self.call("/v1/chat/completions", self.completion(OTHER), key=key)[0], 200)
        self.assertEqual(self.balance(member), 4999993)
        # A request that fails counts nothing.
        self.assertEqual(self.call("/v1/chat/completions", self.completion(MODEL, content="fail"), key=key)[0], 502)
        self.assertEqual(self.call("/api/admin/subscriptions", session=self.admin)[1]["subscribers"][0]["used"], 5)

        # Used up: the balance pays at the token prices.
        with self.service.store.db() as db:
            db.execute("UPDATE subscriptions SET window_used=token_limit WHERE user_id=?", (user,))
        self.assertEqual(self.mine(member)["used_percent"], 100)
        self.assertEqual(self.call("/v1/chat/completions", self.completion(MODEL), key=key)[0], 200)
        self.assertEqual(self.balance(member), 4999986)
        # With too little balance as well, the refusal says when the limit resets.
        with self.service.store.db() as db:
            db.execute("INSERT INTO credit_ledger VALUES('drain',?,?,'test',?,NULL,NULL)", (user, -4999986, int(time.time())))
        status, refused, _ = self.call("/v1/chat/completions", self.completion(MODEL), key=key)
        self.assertEqual(status, 402)
        self.assertIn("limit for this window is reached. It resets at", refused["error"]["message"])

        # The administrator gives a reset: requests are included again.
        subscribers = self.call("/api/admin/subscriptions", session=self.admin)[1]["subscribers"]
        self.assertEqual([s["email"] for s in subscribers], [self.call("/api/session", session=member)[1]["user"]["email"]])
        self.assertEqual(self.call("/api/admin/subscriptions/reset", {"user": user}, member)[0], 403)
        self.assertEqual(self.call("/api/admin/subscriptions/reset", {"user": user}, self.admin)[0], 200)
        self.assertEqual(self.mine(member)["used_percent"], 0)
        self.assertEqual(self.call("/v1/chat/completions", self.completion(MODEL), key=key)[0], 200)

    def test_renewing_adds_thirty_days_on_the_plans_current_terms_and_another_plan_waits(self):
        self.endpoint()
        pro = self.plan(price="5")[1]["plans"][0]
        team = next(p for p in self.plan(name="Team", price="8", millions="3")[1]["plans"] if p["name"] == "Team")
        member, _ = self.funded(15)
        first = self.call("/api/subscriptions/subscribe", {"plan": pro["id"]}, member)[1]["subscription"]
        status, refused, _ = self.call("/api/subscriptions/subscribe", {"plan": team["id"]}, member)
        self.assertEqual(status, 400)
        self.assertIn("Pro subscription is still running", refused["error"]["message"])
        # A paid period keeps its terms when the plan changes, until it is renewed.
        self.plan(id=pro["id"], price="5", millions="2", resets="week", models=(MODEL, OTHER))
        self.assertEqual((self.mine(member)["resets"], self.mine(member)["models"]), ("5h", [MODEL]))
        renewed = self.call("/api/subscriptions/subscribe", {"plan": pro["id"]}, member)[1]["subscription"]
        self.assertEqual(renewed["ends"], first["ends"] + PERIOD)
        self.assertEqual((renewed["resets"], renewed["models"]), ("week", [MODEL, OTHER]))
        self.assertEqual(self.balance(member), 5000000)
        # Not enough left for another period.
        self.assertEqual(self.call("/api/subscriptions/subscribe", {"plan": pro["id"]}, member)[0], 200)
        status, poor, _ = self.call("/api/subscriptions/subscribe", {"plan": pro["id"]}, member)
        self.assertEqual(status, 400)
        self.assertIn("below the price", poor["error"]["message"])

    def test_switched_off_nothing_can_be_bought_and_paid_periods_run_to_their_end(self):
        self.endpoint()
        self.assertEqual(self.call("/api/admin/prices", {"model": MODEL, "input_usd": "1", "output_usd": "2"}, self.admin)[0], 200)
        plan = self.plan(price="5")[1]["plans"][0]
        member, _ = self.funded(10)
        key = self.key(session=member)["key"]
        self.assertEqual(self.call("/api/subscriptions/subscribe", {"plan": plan["id"]}, member)[0], 200)
        self.assertEqual(self.call("/api/admin/subscriptions/switch", {"enabled": False}, member)[0], 403)
        off = self.call("/api/admin/subscriptions/switch", {"enabled": False}, self.admin)[1]
        self.assertFalse(off["enabled"])
        self.assertEqual(len(off["plans"]), 1)
        state = self.call("/api/subscriptions", session=member)[1]
        self.assertEqual((state["enabled"], state["plans"]), (False, []))
        self.assertEqual(state["subscription"]["name"], "Pro")
        status, refused, _ = self.call("/api/subscriptions/subscribe", {"plan": plan["id"]}, member)
        self.assertEqual(status, 400)
        self.assertIn("not offered at the moment", refused["error"]["message"])
        # The period already paid for still includes requests.
        self.assertEqual(self.call("/v1/chat/completions", self.completion(MODEL), key=key)[0], 200)
        self.assertEqual(self.balance(member), 5000000)
        self.assertTrue(self.call("/api/admin/subscriptions/switch", {"enabled": True}, self.admin)[1]["enabled"])
        self.assertEqual(len(self.call("/api/subscriptions", session=member)[1]["plans"]), 1)

    def test_windows_open_at_the_first_request_and_last_five_hours_or_a_week(self):
        now = 1_800_000_000
        for resets, length in (("5h", 5 * 3600), ("week", 7 * 86400)):
            row = {"window_start": now, "window_used": 40, "resets": resets}
            self.assertEqual(window(row, now + length - 1), (now, 40))
            self.assertEqual(window(row, now + length), (None, 0))
        self.assertEqual(window({"window_start": None, "window_used": 0, "resets": "5h"}, now), (None, 0))


if __name__ == "__main__":
    unittest.main()
