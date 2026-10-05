// Derived from Coss UI (MIT). Upstream attribution and terms: LICENSE.txt
"use client"

import { Combobox as ComboboxPrimitive } from "@base-ui/react/combobox"
import { ChevronsUpDownIcon } from "lucide-react"
import type * as React from "react"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { cn } from "@/lib/utils"

export function Combobox<Value, Multiple extends boolean | undefined = false>(
  props: ComboboxPrimitive.Root.Props<Value, Multiple>,
): React.ReactElement {
  return <ComboboxPrimitive.Root {...props} />
}

export function ComboboxInput({
  className,
  size,
  showTrigger = true,
  ...props
}: Omit<ComboboxPrimitive.Input.Props, "size"> & {
  size?: "sm" | "default" | "lg" | number
  showTrigger?: boolean
  ref?: React.Ref<HTMLInputElement>
}): React.ReactElement {
  const sizeValue = (size ?? "default") as "sm" | "default" | "lg" | number
  return (
    <ComboboxPrimitive.InputGroup className="relative w-full text-foreground has-disabled:opacity-64" data-slot="combobox-input-group">
      <ComboboxPrimitive.Input
        className={cn(showTrigger && "*:data-[slot=combobox-input]:pe-8", className)}
        data-slot="combobox-input"
        render={<Input className="has-disabled:opacity-100" nativeInput size={sizeValue} />}
        {...props}
      />
      {showTrigger ? <ComboboxPrimitive.Trigger
        aria-label="Open image list"
        className="absolute end-0.5 top-1/2 inline-flex size-7 -translate-y-1/2 cursor-pointer items-center justify-center rounded-md border border-transparent opacity-80 outline-none hover:opacity-100 focus-visible:ring-2 focus-visible:ring-ring"
        data-slot="combobox-trigger"
      >
        <ComboboxPrimitive.Icon><ChevronsUpDownIcon aria-hidden="true" className="size-4" /></ComboboxPrimitive.Icon>
      </ComboboxPrimitive.Trigger> : null}
    </ComboboxPrimitive.InputGroup>
  )
}

export function ComboboxPopup({
  className,
  children,
  side = "bottom",
  sideOffset = 4,
  align = "start",
  portalProps,
  ...props
}: ComboboxPrimitive.Popup.Props & {
  align?: ComboboxPrimitive.Positioner.Props["align"]
  sideOffset?: ComboboxPrimitive.Positioner.Props["sideOffset"]
  side?: ComboboxPrimitive.Positioner.Props["side"]
  portalProps?: ComboboxPrimitive.Portal.Props
}): React.ReactElement {
  return (
    <ComboboxPrimitive.Portal {...portalProps}>
      <ComboboxPrimitive.Positioner align={align} className="z-50 select-none" side={side} sideOffset={sideOffset}>
        <span className={cn("relative flex max-h-full min-w-(--anchor-width) max-w-(--available-width) rounded-lg border bg-popover shadow-lg/5", className)}>
          <ComboboxPrimitive.Popup className="flex max-h-[min(var(--available-height),23rem)] flex-1 flex-col text-foreground" data-slot="combobox-popup" {...props}>
            {children}
          </ComboboxPrimitive.Popup>
        </span>
      </ComboboxPrimitive.Positioner>
    </ComboboxPrimitive.Portal>
  )
}

export function ComboboxItem({ className, children, ...props }: ComboboxPrimitive.Item.Props): React.ReactElement {
  return (
    <ComboboxPrimitive.Item
      className={cn("grid min-h-9 cursor-default grid-cols-[1rem_minmax(0,1fr)] items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none data-disabled:pointer-events-none data-highlighted:bg-accent data-highlighted:text-accent-foreground data-disabled:opacity-64", className)}
      data-slot="combobox-item"
      {...props}
    >
      <ComboboxPrimitive.ItemIndicator className="col-start-1">
        <svg aria-hidden="true" fill="none" height="16" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 24 24" width="16"><path d="M5.252 12.7 10.2 18.63 18.748 5.37" /></svg>
      </ComboboxPrimitive.ItemIndicator>
      <div className="col-start-2 min-w-0">{children}</div>
    </ComboboxPrimitive.Item>
  )
}

export function ComboboxGroup(props: ComboboxPrimitive.Group.Props): React.ReactElement {
  return <ComboboxPrimitive.Group data-slot="combobox-group" {...props} />
}

export function ComboboxGroupLabel({ className, ...props }: ComboboxPrimitive.GroupLabel.Props): React.ReactElement {
  return <ComboboxPrimitive.GroupLabel className={cn("px-2 py-1.5 font-medium text-muted-foreground text-xs", className)} data-slot="combobox-group-label" {...props} />
}

export function ComboboxEmpty({ className, ...props }: ComboboxPrimitive.Empty.Props): React.ReactElement {
  return <ComboboxPrimitive.Empty className={cn("not-empty:p-3 text-center text-sm text-muted-foreground", className)} data-slot="combobox-empty" {...props} />
}

export function ComboboxList({ className, ...props }: ComboboxPrimitive.List.Props): React.ReactElement {
  return (
    <ScrollArea overscrollContain scrollFade scrollbarGutter>
      <ComboboxPrimitive.List className={cn("not-empty:scroll-py-1 not-empty:px-1 not-empty:py-1 in-data-has-overflow-y:pe-3", className)} data-slot="combobox-list" {...props} />
    </ScrollArea>
  )
}

export const ComboboxCollection = ComboboxPrimitive.Collection
export const ComboboxTrigger = ComboboxPrimitive.Trigger
