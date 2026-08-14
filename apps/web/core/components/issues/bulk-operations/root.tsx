/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useState } from "react";
import { observer } from "mobx-react";
import { useParams } from "next/navigation";
import { X } from "lucide-react";
// plane imports
import { Button } from "@plane/propel/button";
import { TOAST_TYPE, setToast } from "@plane/propel/toast";
import type { TIssue, TIssuePriorities } from "@plane/types";
import { cn } from "@plane/utils";
// components
import { CycleDropdown } from "@/components/dropdowns/cycle";
import { MemberDropdown } from "@/components/dropdowns/member/dropdown";
import { PriorityDropdown } from "@/components/dropdowns/priority";
import { StateDropdown } from "@/components/dropdowns/state/dropdown";
// hooks
import { useIssueDetail } from "@/hooks/store/use-issue-detail";
import { useMultipleSelectStore } from "@/hooks/store/use-multiple-select-store";
import type { TSelectionHelper } from "@/hooks/use-multiple-select";

type Props = {
  className?: string;
  selectionHelpers: TSelectionHelper;
};

/**
 * Apply one change to every selected work item.
 *
 * Upstream gates this behind a paid plan; the selection itself is already in the
 * community build, so this only adds the actions. Each item is patched through the
 * normal update path, which keeps activity, notifications and the board in sync.
 *
 * ponytail: one request per work item rather than a bulk endpoint. Fine for the
 * dozens you can select on screen; add a server-side bulk update if someone starts
 * selecting thousands.
 */
export const IssueBulkOperationsRoot = observer(function IssueBulkOperationsRoot(props: Props) {
  const { className, selectionHelpers } = props;
  // states
  const [isUpdating, setIsUpdating] = useState(false);
  // router
  const { workspaceSlug } = useParams();
  // store hooks
  const { isSelectionActive, selectedEntityIds, clearSelection } = useMultipleSelectStore();
  const {
    updateIssue,
    addIssueToCycle,
    removeIssueFromCycle,
    issue: { getIssueById },
  } = useIssueDetail();

  if (!isSelectionActive || selectionHelpers.isSelectionDisabled) return null;

  const selectedIssues = selectedEntityIds.map((id) => getIssueById(id)).filter((issue): issue is TIssue => !!issue);
  // the dropdowns are project scoped, so they only make sense on one project's work items
  const projectIds = Array.from(new Set(selectedIssues.map((issue) => issue.project_id).filter(Boolean)));
  const projectId = projectIds.length === 1 ? (projectIds[0] as string) : undefined;

  // cycles are a relation, not a field on the work item
  const applyCycle = async (cycleId: string | null) => {
    if (!workspaceSlug || !projectId) return;
    setIsUpdating(true);
    try {
      if (cycleId) {
        await addIssueToCycle(workspaceSlug.toString(), projectId, cycleId, selectedIssues.map((issue) => issue.id));
      } else {
        await Promise.all(
          selectedIssues
            .filter((issue) => issue.cycle_id)
            .map((issue) =>
              removeIssueFromCycle(workspaceSlug.toString(), projectId, issue.cycle_id as string, issue.id)
            )
        );
      }
      setToast({
        type: TOAST_TYPE.SUCCESS,
        title: "Updated",
        message: `${selectedIssues.length} work item${selectedIssues.length > 1 ? "s" : ""}: cycle`,
      });
    } catch {
      setToast({ type: TOAST_TYPE.ERROR, title: "Could not move every work item", message: "Try again." });
    } finally {
      setIsUpdating(false);
    }
  };

  const applyToSelection = async (data: Partial<TIssue>, label: string) => {
    if (!workspaceSlug) return;
    setIsUpdating(true);
    try {
      await Promise.all(
        selectedIssues.map((issue) =>
          updateIssue(workspaceSlug.toString(), issue.project_id as string, issue.id, data)
        )
      );
      setToast({
        type: TOAST_TYPE.SUCCESS,
        title: "Updated",
        message: `${selectedIssues.length} work item${selectedIssues.length > 1 ? "s" : ""}: ${label}`,
      });
    } catch {
      setToast({
        type: TOAST_TYPE.ERROR,
        title: "Could not update every work item",
        message: "Some items were left unchanged. Try again.",
      });
    } finally {
      setIsUpdating(false);
    }
  };

  return (
    <div className={cn("sticky bottom-0 left-0 z-[2] grid h-20 place-items-center px-3.5", className)}>
      <div className="border-subtle bg-surface-1 flex h-14 w-full items-center gap-3 rounded-md border px-3.5 py-4 shadow-lg">
        <span className="text-13 flex-shrink-0 font-medium">
          {selectedEntityIds.length} selected
        </span>

        {projectId ? (
          <div className={cn("flex flex-wrap items-center gap-2", isUpdating && "pointer-events-none opacity-60")}>
            <StateDropdown
              value={undefined}
              projectId={projectId}
              onChange={(stateId) => applyToSelection({ state_id: stateId }, "state")}
              buttonVariant="border-with-text"
            />
            <PriorityDropdown
              value={undefined}
              onChange={(priority: TIssuePriorities) => applyToSelection({ priority }, "priority")}
              buttonVariant="border-with-text"
            />
            <MemberDropdown
              projectId={projectId}
              value={[]}
              onChange={(assigneeIds: string[]) => applyToSelection({ assignee_ids: assigneeIds }, "assignees")}
              buttonVariant="border-with-text"
              multiple
              placeholder="Assignees"
            />
            <CycleDropdown
              projectId={projectId}
              value={null}
              onChange={applyCycle}
              buttonVariant="border-with-text"
              placeholder="Cycle"
            />
          </div>
        ) : (
          <span className="text-13 text-tertiary">
            Select work items from a single project to change them together.
          </span>
        )}

        <Button variant="link" size="sm" className="ml-auto flex-shrink-0" onClick={clearSelection}>
          <X className="size-3.5" />
          Clear
        </Button>
      </div>
    </div>
  );
});
