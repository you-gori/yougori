import { expect, it } from "vitest"
import { parseSshCommand } from "./ssh-command"

it("reads the EC2 Connect example command", () => {
  expect(parseSshCommand('ssh -i "my key.pem" ec2-user@ec2-203-0-113-25.compute-1.amazonaws.com')).toEqual({ username: "ec2-user", host: "ec2-203-0-113-25.compute-1.amazonaws.com", port: undefined, key: "my key.pem" })
  expect(parseSshCommand("ssh -p 2222 -i C:/Keys/a.pem ubuntu@203.0.113.25")).toEqual({ username: "ubuntu", host: "203.0.113.25", port: 2222, key: "C:/Keys/a.pem" })
  expect(parseSshCommand("ssh -o StrictHostKeyChecking=no -l admin 203.0.113.25")).toMatchObject({ username: "admin", host: "203.0.113.25" })
})

it("ignores text that is not an ssh command", () => {
  expect(parseSshCommand("ec2-user@203.0.113.25")).toBeNull()
  expect(parseSshCommand("ssh -i key.pem")).toBeNull()
  expect(parseSshCommand("ssh -p 0 ubuntu@host")).toBeNull()
})
