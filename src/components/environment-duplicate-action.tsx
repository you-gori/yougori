import { CopyIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Menu, MenuItem, MenuPopup, MenuTrigger } from "@/components/ui/menu"

export type DuplicateDestination = "local" | "cloud"

export function EnvironmentDuplicateAction({ name, disabled, onSelect }: {
  name: string
  disabled?: boolean
  onSelect(destination: DuplicateDestination): void
}) {
  return <Menu>
    <MenuTrigger render={<Button aria-label={`Duplicate ${name}`} title="Duplicate environment" disabled={disabled} size="icon-xs" type="button" variant="ghost" className="shrink-0" />}>
      <CopyIcon aria-hidden="true" />
    </MenuTrigger>
    <MenuPopup align="start">
      <MenuItem onClick={() => onSelect("local")}>Local</MenuItem>
      <MenuItem onClick={() => onSelect("cloud")}>Cloud</MenuItem>
    </MenuPopup>
  </Menu>
}
