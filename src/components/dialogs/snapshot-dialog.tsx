import { useEffect, useState, type FormEvent, type ReactNode } from "react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogClose,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogPanel,
  DialogPopup,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Form } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { usePlatform } from "@/context/platform-context"

export function SnapshotDialog({ environmentId, environmentName, trigger, open: controlledOpen, onOpenChange: controlledChange }: {
  environmentId: string
  environmentName: string
  trigger?: ReactNode
  open?: boolean
  onOpenChange?(open: boolean): void
}) {
  const { createSnapshot } = usePlatform()
  const [internalOpen, setInternalOpen] = useState(false)
  const [name, setName] = useState("")
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState("")
  const open = controlledOpen ?? internalOpen
  const setOpen = controlledChange ?? setInternalOpen

  useEffect(() => {
    if (!open) return
    setName(`Snapshot ${new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(new Date())}`)
    setError("")
  }, [open])

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (saving || !name.trim()) return
    setSaving(true)
    setError("")
    try {
      await createSnapshot(environmentId, name.trim())
      setOpen(false)
    } catch (reason) {
      // A failed snapshot keeps the popup open and says why, rather than closing on nothing.
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog onOpenChange={value => { if (!saving) setOpen(value) }} open={open}>
      {trigger ? <DialogTrigger render={trigger as React.ReactElement} /> : null}
      <DialogPopup className="sm:max-w-xl" closeProps={{ disabled: saving }}>
        <DialogHeader>
          <DialogTitle>Create snapshot</DialogTitle>
          <DialogDescription>Saves {environmentName} as it is now, so you can return to this point later. The snapshot stays on this computer.</DialogDescription>
        </DialogHeader>
        <Form className="contents" onSubmit={submit}>
          <DialogPanel className="space-y-3">
            <Field name="snapshot-name">
              <FieldLabel>Name</FieldLabel>
              <Input autoFocus disabled={saving} onChange={(event) => setName(event.target.value)} required type="text" value={name} />
              <FieldDescription>It only takes up the space of what changed since the last snapshot.</FieldDescription>
            </Field>
            {error ? <p role="alert" className="break-words text-sm text-destructive-foreground">{error}</p> : null}
          </DialogPanel>
          <DialogFooter>
            <DialogClose render={<Button disabled={saving} type="button" variant="ghost" />}>Cancel</DialogClose>
            <Button disabled={!name.trim()} loading={saving} type="submit">Create snapshot</Button>
          </DialogFooter>
        </Form>
      </DialogPopup>
    </Dialog>
  )
}
