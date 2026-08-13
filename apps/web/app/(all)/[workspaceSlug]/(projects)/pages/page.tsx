/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useMemo, useState } from "react";
import { observer } from "mobx-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import useSWR from "swr";
import { Search } from "lucide-react";
// plane imports
import { PageIcon } from "@plane/propel/icons";
import type { TPage } from "@plane/types";
import { renderFormattedDate } from "@plane/utils";
// components
import { PageHead } from "@/components/core/page-title";
// hooks
import { useProject } from "@/hooks/store/use-project";
// services
import { ProjectPageService } from "@/services/page";

const pageService = new ProjectPageService();

function WorkspacePagesPage() {
  const { workspaceSlug } = useParams();
  const [query, setQuery] = useState("");
  const { getProjectById } = useProject();

  const { data, isLoading } = useSWR(
    workspaceSlug ? `WORKSPACE_PAGES_${workspaceSlug}` : null,
    workspaceSlug ? () => pageService.fetchAllInWorkspace(workspaceSlug.toString()) : null
  );

  // group pages by their project, so every project's documents sit together
  const groups = useMemo(() => {
    const filtered = (data ?? []).filter((page: TPage) =>
      (page.name ?? "").toLowerCase().includes(query.toLowerCase().trim())
    );
    const byProject = new Map<string, TPage[]>();
    filtered.forEach((page: TPage) => {
      const projectId = page.project_ids?.[0];
      if (!projectId) return;
      byProject.set(projectId, [...(byProject.get(projectId) ?? []), page]);
    });
    return Array.from(byProject.entries())
      .map(([projectId, pages]) => ({ projectId, name: getProjectById(projectId)?.name ?? "Project", pages }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [data, query, getProjectById]);

  return (
    <>
      <PageHead title="Pages" />
      <div className="h-full w-full overflow-y-auto px-6 py-5">
        <div className="mb-4 flex items-center gap-2 rounded-md border border-subtle px-2 py-1">
          <Search className="size-3.5 text-placeholder" />
          <input
            className="w-full bg-transparent text-sm outline-none"
            placeholder="Search pages"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        {isLoading && <p className="text-sm text-placeholder">Loading…</p>}
        {!isLoading && groups.length === 0 && <p className="text-sm text-placeholder">No pages yet.</p>}
        {groups.map((group) => (
          <div key={group.projectId} className="mb-6">
            <h3 className="mb-2 text-13 font-semibold text-secondary">{group.name}</h3>
            <div className="flex flex-col">
              {group.pages.map((page) => (
                <Link
                  key={page.id}
                  href={`/${workspaceSlug}/projects/${group.projectId}/pages/${page.id}`}
                  className="flex items-center justify-between gap-4 rounded-sm px-2 py-1.5 hover:bg-layer-transparent-hover"
                >
                  <span className="flex min-w-0 items-center gap-2">
                    <PageIcon className="size-4 flex-shrink-0 text-placeholder" />
                    <span className="truncate text-sm">{page.name || "Untitled"}</span>
                  </span>
                  <span className="flex-shrink-0 text-xs text-placeholder">
                    {page.updated_at ? renderFormattedDate(page.updated_at) : ""}
                  </span>
                </Link>
              ))}
            </div>
          </div>
        ))}
      </div>
    </>
  );
}

export default observer(WorkspacePagesPage);
