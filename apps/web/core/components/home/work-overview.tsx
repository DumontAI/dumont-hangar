/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { observer } from "mobx-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import useSWR from "swr";
// plane imports
import { STATE_GROUPS } from "@plane/constants";
import type { TStateGroups, WorkItemInsightColumns } from "@plane/types";
import { Card, ECardDirection, ECardSpacing, Loader } from "@plane/ui";
// services
import { AnalyticsService } from "@/services/analytics.service";

const analyticsService = new AnalyticsService();

// state groups we surface, in the order work flows through them
const TILES: { group: TStateGroups; label: string; column: keyof WorkItemInsightColumns }[] = [
  { group: "backlog", label: "Backlog", column: "backlog_work_items" },
  { group: "unstarted", label: "Not started", column: "un_started_work_items" },
  { group: "started", label: "Working on", column: "started_work_items" },
  { group: "completed", label: "Completed", column: "completed_work_items" },
];

const count = (project: WorkItemInsightColumns, column: keyof WorkItemInsightColumns): number =>
  typeof project[column] === "number" ? (project[column] as number) : 0;

const openCount = (project: WorkItemInsightColumns): number =>
  project.backlog_work_items + project.un_started_work_items + project.started_work_items;

export const HomeWorkOverview = observer(function HomeWorkOverview() {
  // router
  const { workspaceSlug } = useParams();
  const slug = workspaceSlug?.toString();

  const { data: projects, error } = useSWR(
    slug ? `WORKSPACE_WORK_ITEM_INSIGHTS_${slug}` : null,
    slug ? () => analyticsService.getAdvanceAnalyticsStats<WorkItemInsightColumns[]>(slug, "work-items") : null
  );

  // members without analytics access get a 403 here — stay out of the way rather than pin a skeleton
  if (!slug || error) return null;

  const withWork = (projects ?? []).filter((project) => openCount(project) > 0);
  const busiest = [...withWork].sort((a, b) => openCount(b) - openCount(a)).slice(0, 5);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-16 font-medium">Across the workspace</h3>
        <Link href={`/${slug}/analytics`} className="text-13 text-placeholder hover:text-primary">
          Analytics
        </Link>
      </div>
      {projects ? (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {TILES.map((tile) => (
              <Card
                key={tile.group}
                direction={ECardDirection.ROW}
                spacing={ECardSpacing.SM}
                className="h-full items-center"
              >
                <div
                  className="h-3 w-3 shrink-0 rounded-xs"
                  style={{ backgroundColor: STATE_GROUPS[tile.group].color }}
                />
                <div className="min-w-0 space-y-1">
                  <p className="truncate text-13 text-placeholder">{tile.label}</p>
                  <p className="text-18 font-semibold">
                    {projects.reduce((sum, project) => sum + count(project, tile.column), 0)}
                  </p>
                </div>
              </Card>
            ))}
          </div>
          {busiest.length > 0 && (
            <Card spacing={ECardSpacing.SM} className="gap-0">
              {busiest.map((project) => (
                <Link
                  key={project.project_id}
                  href={`/${slug}/projects/${project.project_id}/issues`}
                  className="flex items-center gap-3 rounded-sm px-2 py-2 hover:bg-layer-1"
                >
                  <span className="w-40 shrink-0 truncate text-13 font-medium">{project.project__name}</span>
                  <span className="flex h-2 flex-1 overflow-hidden rounded-full bg-layer-1">
                    {TILES.filter((tile) => tile.group !== "completed").map((tile) => (
                      <span
                        key={tile.group}
                        style={{
                          backgroundColor: STATE_GROUPS[tile.group].color,
                          width: `${(count(project, tile.column) / openCount(project)) * 100}%`,
                        }}
                      />
                    ))}
                  </span>
                  <span className="w-24 shrink-0 text-right text-13 text-placeholder">{openCount(project)} open</span>
                </Link>
              ))}
            </Card>
          )}
        </>
      ) : (
        <Loader className="space-y-3">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {TILES.map((tile) => (
              <Loader.Item key={tile.group} height="66px" />
            ))}
          </div>
          <Loader.Item height="150px" />
        </Loader>
      )}
    </div>
  );
});
