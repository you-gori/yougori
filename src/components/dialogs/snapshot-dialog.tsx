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
  const open = controlledOpen ?? internalOpen
  const setOpen = controlledChange ?? setInternalOpen

  useEffect(() => {
    if (open) setName(`Snapshot ${new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(new Date())}`)
  }, [open])

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setSaving(true)
    try {
      await createSnapshot(environmentId, name.trim())
      setOpen(false)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog onOpenChange={setOpen} open={open}>
      {trigger ? <DialogTrigger render={trigger as React.ReactElement} /> : null}
      <DialogPopup className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Create snapshot</DialogTitle>
          <DialogDescription>Capture {environmentName} as a local copy-on-write restore point.</DialogDescription>
        </DialogHeader>
        <Form className="contents" onSubmit={submit}>
          <DialogPanel>
            <Field name="snapshot-name">
              <FieldLabel>Name</FieldLabel>
              <Input autoFocus onChange={(event) => setName(event.target.value)} required type="text" value={name} />
              <FieldDescription>Only blocks changed since the last snapshot use additional space.</FieldDescription>
            </Field>
          </DialogPanel>
          <DialogFooter>
            <DialogClose render={<Button type="button" variant="ghost" />}>Cancel</DialogClose>
            <Button loading={saving} type="submit">Create snapshot</Button>
          </DialogFooter>
        </Form>
      </DialogPopup>
    </Dialog>
  )
}
