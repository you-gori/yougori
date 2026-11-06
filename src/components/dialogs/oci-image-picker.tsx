import { useId, useState } from "react"
import { ChevronDownIcon, SearchIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Combobox, ComboboxCollection, ComboboxEmpty, ComboboxGroup, ComboboxGroupLabel, ComboboxInput, ComboboxItem,
  ComboboxList, ComboboxPopup, ComboboxTrigger,
} from "@/components/ui/combobox"
import { customOciImage, ociImageGroups, ociRegistryLabel, type OciImageGroup, type OciImageOption } from "@/data/oci-images"
import { matchesOciImage } from "@/data/container-purposes"

export function OciImagePicker({ value, onChange, disabled, groups = ociImageGroups, onOpen }: {
  value: OciImageOption
  onChange(image: OciImageOption): void
  disabled: boolean
  groups?: OciImageGroup[]
  onOpen?(): void
}) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")
  const searchLabelId = useId()
  return (
    <Combobox
      autoHighlight disabled={disabled} filter={matchesOciImage}
      inputValue={query} onInputValueChange={setQuery}
      itemToStringLabel={image => image.label} itemToStringValue={image => image.value}
      items={groups} value={value} open={open}
      onOpenChange={nextOpen => { setOpen(nextOpen); if (nextOpen) { setQuery(""); onOpen?.() } }}
      onValueChange={image => { if (image) onChange(image) }}
    >
      <ComboboxTrigger
        className="creation-image-trigger"
        render={<Button type="button" variant="outline" />}
      >
        <SearchIcon aria-hidden="true" />
        <span className="creation-selected-image">
          <span>{value.label}</span>
          <span>{value.displayReference ?? (value === customOciImage ? "Your own image" : value.builtin ? value.description : value.value)}</span>
        </span>
        <ChevronDownIcon aria-hidden="true" className="creation-image-chevron" />
      </ComboboxTrigger>
      <ComboboxPopup aria-label="OCI image catalog" className="creation-image-popup">
        <div className="creation-image-search">
          <span className="sr-only" id={searchLabelId}>Search OCI images</span>
          <SearchIcon aria-hidden="true" />
          <ComboboxInput
            aria-labelledby={searchLabelId} autoFocus type="text" showTrigger={false}
            placeholder="Search images, purpose, or registry…"
          />
        </div>
        <ComboboxEmpty>No matching images in the catalog. Try another search or use your own image below.</ComboboxEmpty>
        <ComboboxList>
          {(group: OciImageGroup) => (
            <ComboboxGroup key={group.value} items={group.items} className="not-first:mt-2 not-first:border-t not-first:border-border not-first:pt-2">
              <ComboboxGroupLabel className="px-3 text-foreground">{group.value}</ComboboxGroupLabel>
              <ComboboxCollection>
                {(image: OciImageOption) => (
                  <ComboboxItem key={image.value} value={image} disabled={image.disabled}>
                    <span className="creation-image-result">
                      <span className="creation-image-result-heading">
                        <span>{image.label}</span>
                        <span>{image.badge ?? (image === customOciImage ? "Any registry" : image.builtin ? "Built in" : ociRegistryLabel(image.value))}</span>
                      </span>
                      <span className="creation-image-reference">{image.displayReference ?? (image === customOciImage || image.builtin ? image.description : image.value)}</span>
                      {image !== customOciImage && !image.builtin ? <span className="creation-image-description">{image.description}</span> : null}
                    </span>
                  </ComboboxItem>
                )}
              </ComboboxCollection>
            </ComboboxGroup>
          )}
        </ComboboxList>
        <div className="creation-image-custom">
          <span>Have your own image?</span>
          <Button disabled={disabled} type="button" variant="ghost" size="sm" onClick={() => {
            onChange(customOciImage)
            setOpen(false)
          }}>Use custom image</Button>
        </div>
      </ComboboxPopup>
    </Combobox>
  )
}
