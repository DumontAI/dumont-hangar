/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { observer } from "mobx-react";
import { ArrowLeft } from "lucide-react";
// plane imports
import { useTranslation } from "@plane/i18n";
import { InboxIcon } from "@plane/propel/icons";
import { Breadcrumbs, Header } from "@plane/ui";
// components
import { BreadcrumbLink } from "@/components/common/breadcrumb-link";
// hooks
import { useAppRouter } from "@/hooks/use-app-router";
// local imports
import { NotificationSidebarHeaderOptions } from "./options";

type TNotificationSidebarHeader = {
  workspaceSlug: string;
};

export const NotificationSidebarHeader = observer(function NotificationSidebarHeader(
  props: TNotificationSidebarHeader
) {
  const { workspaceSlug } = props;
  const { t } = useTranslation();
  const router = useAppRouter();

  // the inbox is a destination, not a page in a flow: leaving it should put you
  // back on whatever you were doing, not on the workspace home
  const handleBack = () => {
    if (typeof window !== "undefined" && window.history.length > 1) router.back();
    else router.push(`/${workspaceSlug}/`);
  };

  if (!workspaceSlug) return <></>;
  return (
    <Header className="my-auto bg-surface-1">
      <Header.LeftItem>
        <button
          type="button"
          onClick={handleBack}
          title="Back to where you were"
          className="mr-1 flex flex-shrink-0 items-center gap-1 text-13 text-tertiary hover:text-secondary"
        >
          <ArrowLeft className="size-4" />
          Back
        </button>
        <Breadcrumbs>
          <Breadcrumbs.Item
            component={
              <BreadcrumbLink
                label={t("notification.label")}
                icon={<InboxIcon className="h-4 w-4 text-primary" />}
                disableTooltip
              />
            }
          />
        </Breadcrumbs>
      </Header.LeftItem>
      <Header.RightItem>
        <NotificationSidebarHeaderOptions workspaceSlug={workspaceSlug} />
      </Header.RightItem>
    </Header>
  );
});
