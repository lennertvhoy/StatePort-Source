import * as React from "react"
import { GripVerticalIcon } from "lucide-react"
import * as ResizablePrimitive from "react-resizable-panels"

import { cn } from "@/lib/utils"

/**
 * PanelGroup — accessibility-fixed wrapper around react-resizable-panels'
 * Group. The library (v4) renders the group as a plain <div> with an
 * aria-orientation attribute but no role; axe flags this as aria-allowed-attr
 * because aria-orientation is only valid on certain roles (e.g. separator).
 * Orientation is already conveyed accessibly by each Separator
 * (role="separator" + aria-orientation), so the redundant attribute on the
 * group element is stripped here via the library's elementRef callback.
 */
function PanelGroup({ elementRef, ...props }: React.ComponentProps<typeof ResizablePrimitive.Group>) {
  const stripAriaOrientationRef = React.useCallback(
    (el: HTMLDivElement | null) => {
      el?.removeAttribute("aria-orientation")
      if (typeof elementRef === "function") {
        elementRef(el)
      } else if (elementRef) {
        // Canonical merge-refs forwarding: this assignment runs inside the
        // callback ref (outside render), which the rule cannot see.
        // eslint-disable-next-line react-hooks/immutability
        elementRef.current = el
      }
    },
    [elementRef]
  )
  return <ResizablePrimitive.Group elementRef={stripAriaOrientationRef} {...props} />
}

function ResizablePanelGroup({
  className,
  ...props
}: React.ComponentProps<typeof ResizablePrimitive.Group>) {
  return (
    <ResizablePrimitive.Group
      data-slot="resizable-panel-group"
      className={cn(
        "flex h-full w-full data-[panel-group-direction=vertical]:flex-col",
        className
      )}
      {...props}
    />
  )
}

function ResizablePanel({
  ...props
}: React.ComponentProps<typeof ResizablePrimitive.Panel>) {
  return <ResizablePrimitive.Panel data-slot="resizable-panel" {...props} />
}

function ResizableHandle({
  withHandle,
  className,
  ...props
}: React.ComponentProps<typeof ResizablePrimitive.Separator> & {
  withHandle?: boolean
}) {
  return (
    <ResizablePrimitive.Separator
      data-slot="resizable-handle"
      className={cn(
        "bg-border focus-visible:ring-ring relative flex w-px items-center justify-center after:absolute after:inset-y-0 after:left-1/2 after:w-1 after:-translate-x-1/2 focus-visible:ring-1 focus-visible:ring-offset-1 focus-visible:outline-hidden data-[panel-group-direction=vertical]:h-px data-[panel-group-direction=vertical]:w-full data-[panel-group-direction=vertical]:after:left-0 data-[panel-group-direction=vertical]:after:h-1 data-[panel-group-direction=vertical]:after:w-full data-[panel-group-direction=vertical]:after:translate-x-0 data-[panel-group-direction=vertical]:after:-translate-y-1/2 [&[data-panel-group-direction=vertical]>div]:rotate-90",
        className
      )}
      {...props}
    >
      {withHandle && (
        <div className="bg-border z-10 flex h-4 w-3 items-center justify-center rounded-xs border">
          <GripVerticalIcon className="size-2.5" />
        </div>
      )}
    </ResizablePrimitive.Separator>
  )
}

export { PanelGroup, ResizablePanelGroup, ResizablePanel, ResizableHandle }
