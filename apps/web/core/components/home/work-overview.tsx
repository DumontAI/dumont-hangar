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
import { STATE_GROUPS, USER_PROFILE_DATA } from "@plane/constants";
import type { TStateGroups } from "@plane/types";
import { Card, ECardDirection, ECardSpacing, Loader } from "@plane/ui";
// hooks
import { useUser } from "@/hooks/store/user";
// services
import { UserService } from "@/services/user.service";

const userService = new UserService();

const STATE_TILES: { group: TStateGroups; label: string }[] = [
  { group: "backlog", label: "Backlog" },
  { group: "unstarted", label: "Not started" },
  { group: "started", label: "Working on" },
  { group: "completed", label: "Completed" },
];

export const HomeWorkOverview = observer(function HomeWorkOverview() {
  // router
  const { workspaceSlug } = useParams();
  // store hooks
  const { data: currentUser } = useUser();
  // derived values
  const userId = currentUser?.id;

  const { data: profile } = useSWR(
    workspaceSlug && userId ? USER_PROFILE_DATA(workspaceSlug.toString(), userId) : null,
    workspaceSlug && userId ? () => userService.getUserProfileData(workspaceSlug.toString(), userId) : null
  );

  if (!workspaceSlug || !userId) return null;

  const profileLink = `/${workspaceSlug.toString()}/profile/${userId}`;
  const tiles = [
    ...STATE_TILES.map((tile) => ({
      key: tile.group,
      label: tile.label,
      value: profile?.state_distribution.find((s) => s.state_group === tile.group)?.state_count ?? 0,
      color: STATE_GROUPS[tile.group].color,
      href: `${profileLink}/assigned`,
    })),
    {
      key: "created",
      label: "Created by you",
      value: profile?.created_issues ?? 0,
      color: "var(--background-color-accent-primary)",
      href: `${profileLink}/created`,
    },
  ];

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-16 font-medium">Your work</h3>
        <Link href={`${profileLink}/assigned`} className="text-13 text-placeholder hover:text-primary">
          View all
        </Link>
      </div>
      {profile ? (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          {tiles.map((tile) => (
            <Link key={tile.key} href={tile.href}>
              <Card direction={ECardDirection.ROW} spacing={ECardSpacing.SM} className="h-full items-center">
                <div className="h-3 w-3 shrink-0 rounded-xs" style={{ backgroundColor: tile.color }} />
                <div className="min-w-0 space-y-1">
                  <p className="truncate text-13 text-placeholder">{tile.label}</p>
                  <p className="text-18 font-semibold">{tile.value}</p>
                </div>
              </Card>
            </Link>
          ))}
        </div>
      ) : (
        <Loader className="grid grid-cols-2 gap-3 md:grid-cols-5">
          {tiles.map((tile) => (
            <Loader.Item key={tile.key} height="66px" />
          ))}
        </Loader>
      )}
    </div>
  );
});
