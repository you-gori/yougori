# Example answers

Non-sensitive answers for a scripted run. The image name is an example; use your own.

```text
yougori template run ./examples/hub/host-my-app --inputs answers/private.json --secrets - --yes
```

Pass `app_secret` as JSON on standard input if your app needs one, or `{}` if it does not.
