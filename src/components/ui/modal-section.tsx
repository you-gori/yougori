// Derived from Coss UI (MIT). Upstream attribution and terms: LICENSE.txt
import { mergeProps } from "@base-ui/react/merge-props";
import { useRender } from "@base-ui/react/use-render";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

/** Share polymorphic rendering and scrolling while each modal supplies its layout. */
export function ModalSection({
  sectionSlot,
  baseClassName,
  className,
  render,
  scrollFade,
  ...props
}: useRender.ComponentProps<"div"> & {
  sectionSlot: string;
  baseClassName: string;
  scrollFade?: boolean;
}) {
  const defaultProps = { className: cn(baseClassName, className), "data-slot": sectionSlot };
  const content = useRender({
    defaultTagName: "div",
    props: mergeProps<"div">(defaultProps, props),
    render,
  });
  return scrollFade === undefined ? content : (
    <ScrollArea overscrollContain scrollFade={scrollFade}>{content}</ScrollArea>
  );
}
