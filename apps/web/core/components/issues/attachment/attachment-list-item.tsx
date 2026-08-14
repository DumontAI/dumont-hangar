/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useState } from "react";
import { observer } from "mobx-react";

import { useTranslation } from "@plane/i18n";
import { Download } from "lucide-react";
import { TrashIcon } from "@plane/propel/icons";
import { Tooltip } from "@plane/propel/tooltip";
import type { TIssueServiceType } from "@plane/types";
import { EIssueServiceType } from "@plane/types";
// ui
import { CustomMenu } from "@plane/ui";
import { convertBytesToSize, getFileExtension, getFileName, getFileURL, renderFormattedDate } from "@plane/utils";
// components
//
import { ButtonAvatars } from "@/components/dropdowns/member/avatar";
import { getFileIcon } from "@/components/icons";
import { IssueAttachmentPreviewModal } from "@/components/issues/attachment/attachment-preview-modal";
// helpers
// hooks
import { useIssueDetail } from "@/hooks/store/use-issue-detail";
import { useMember } from "@/hooks/store/use-member";
import { usePlatformOS } from "@/hooks/use-platform-os";

type TIssueAttachmentsListItem = {
  attachmentId: string;
  disabled?: boolean;
  issueServiceType?: TIssueServiceType;
};

export const IssueAttachmentsListItem = observer(function IssueAttachmentsListItem(props: TIssueAttachmentsListItem) {
  const { t } = useTranslation();
  // props
  const { attachmentId, disabled, issueServiceType = EIssueServiceType.ISSUES } = props;
  // store hooks
  const { getUserDetails } = useMember();
  const {
    attachment: { getAttachmentById },
    toggleDeleteAttachmentModal,
  } = useIssueDetail(issueServiceType);
  // derived values
  const attachment = attachmentId ? getAttachmentById(attachmentId) : undefined;
  const fileName = getFileName(attachment?.attributes.name ?? "");
  const fileExtension = getFileExtension(attachment?.attributes.name ?? "");
  const fileIcon = getFileIcon(fileExtension, 18);
  const fileURL = getFileURL(attachment?.asset_url ?? "") ?? "";
  const downloadURL = fileURL ? `${fileURL}${fileURL.includes("?") ? "&" : "?"}download=1` : "";
  // states
  const [isPreviewOpen, setIsPreviewOpen] = useState(false);
  // hooks
  const { isMobile } = usePlatformOS();

  if (!attachment) return <></>;

  return (
    <>
      <IssueAttachmentPreviewModal
        isOpen={isPreviewOpen}
        onClose={() => setIsPreviewOpen(false)}
        name={`${fileName}.${fileExtension}`}
        size={attachment.attributes.size}
        type={attachment.attributes.type}
        src={fileURL}
        downloadSrc={downloadURL}
      />
      <button
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setIsPreviewOpen(true);
        }}
      >
        <div className="group flex h-11 items-center justify-between gap-3 pr-2 pl-9 hover:bg-surface-2">
          <div className="flex items-center gap-3 truncate text-13">
            <div className="flex items-center gap-3">{fileIcon}</div>
            <Tooltip tooltipContent={`${fileName}.${fileExtension}`} isMobile={isMobile}>
              <p className="truncate font-medium text-secondary">{`${fileName}.${fileExtension}`}</p>
            </Tooltip>
            <span className="flex size-1.5 rounded-full bg-layer-1" />
            <span className="flex-shrink-0 text-placeholder">{convertBytesToSize(attachment.attributes.size)}</span>
          </div>

          <div className="flex items-center gap-3">
            {attachment?.created_by && (
              <>
                <Tooltip
                  isMobile={isMobile}
                  tooltipContent={`${
                    getUserDetails(attachment?.created_by)?.display_name ?? ""
                  } uploaded on ${renderFormattedDate(attachment.updated_at)}`}
                >
                  <div className="flex items-center justify-center">
                    <ButtonAvatars showTooltip userIds={attachment?.created_by} />
                  </div>
                </Tooltip>
              </>
            )}

            <CustomMenu ellipsis closeOnSelect placement="bottom-end">
              <CustomMenu.MenuItem
                onClick={() => {
                  window.open(downloadURL, "_blank");
                }}
              >
                <div className="flex items-center gap-2">
                  <Download className="h-3.5 w-3.5" strokeWidth={2} />
                  <span>Download</span>
                </div>
              </CustomMenu.MenuItem>
              <CustomMenu.MenuItem
                disabled={disabled}
                onClick={() => {
                  toggleDeleteAttachmentModal(attachmentId);
                }}
              >
                <div className="flex items-center gap-2">
                  <TrashIcon className="h-3.5 w-3.5" strokeWidth={2} />
                  <span>{t("common.actions.delete")}</span>
                </div>
              </CustomMenu.MenuItem>
            </CustomMenu>
          </div>
        </div>
      </button>
    </>
  );
});
