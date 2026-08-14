/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { Download, ExternalLink, X } from "lucide-react";
// plane imports
import { Button } from "@plane/propel/button";
import { EModalPosition, EModalWidth, ModalCore } from "@plane/ui";
import { convertBytesToSize } from "@plane/utils";

type Props = {
  isOpen: boolean;
  onClose: () => void;
  name: string;
  size?: number;
  type?: string;
  /** inline URL, used for the preview */
  src: string;
  /** same asset with content-disposition attachment */
  downloadSrc: string;
};

/** What a browser can show without help. Everything else gets the download card. */
const previewOf = (type: string, name: string) => {
  const mime = (type || "").toLowerCase();
  const extension = name.split(".").pop()?.toLowerCase() ?? "";
  if (mime.startsWith("image/") || ["png", "jpg", "jpeg", "gif", "webp", "avif", "bmp"].includes(extension))
    return "image";
  if (mime === "application/pdf" || extension === "pdf") return "pdf";
  if (mime.startsWith("video/") || ["mp4", "webm", "mov", "m4v"].includes(extension)) return "video";
  if (mime.startsWith("audio/") || ["mp3", "wav", "m4a", "ogg"].includes(extension)) return "audio";
  if (mime.startsWith("text/") || ["txt", "csv", "log", "md"].includes(extension)) return "text";
  return "none";
};

export function IssueAttachmentPreviewModal(props: Props) {
  const { isOpen, onClose, name, size, type = "", src, downloadSrc } = props;
  const kind = previewOf(type, name);

  return (
    <ModalCore isOpen={isOpen} handleClose={onClose} position={EModalPosition.CENTER} width={EModalWidth.VIXL}>
      <div className="flex items-center justify-between gap-3 border-b border-subtle px-4 py-3">
        <div className="min-w-0">
          <p className="truncate text-13 font-medium">{name}</p>
          {size !== undefined && <p className="text-11 text-tertiary">{convertBytesToSize(size)}</p>}
        </div>
        <div className="flex flex-shrink-0 items-center gap-2">
          <a href={src} target="_blank" rel="noopener noreferrer">
            <Button variant="secondary" size="sm">
              <ExternalLink className="size-3.5" />
              Open
            </Button>
          </a>
          <a href={downloadSrc} target="_blank" rel="noopener noreferrer">
            <Button variant="secondary" size="sm">
              <Download className="size-3.5" />
              Download
            </Button>
          </a>
          <button type="button" onClick={onClose} aria-label="Close preview" className="p-1 text-tertiary">
            <X className="size-4" />
          </button>
        </div>
      </div>

      <div className="grid max-h-[75vh] min-h-[240px] place-items-center overflow-auto bg-layer-1 p-3">
        {kind === "image" && <img src={src} alt={name} className="max-h-[70vh] max-w-full object-contain" />}
        {(kind === "pdf" || kind === "text") && (
          <iframe src={src} title={name} className="h-[70vh] w-full rounded-sm bg-white" />
        )}
        {kind === "video" && <video src={src} controls className="max-h-[70vh] max-w-full" />}
        {kind === "audio" && <audio src={src} controls className="w-full" />}
        {kind === "none" && (
          <div className="p-8 text-center">
            <p className="text-13 text-secondary">This file type can&apos;t be previewed in the browser.</p>
            <a href={downloadSrc} target="_blank" rel="noopener noreferrer" className="mt-3 inline-block">
              <Button variant="primary" size="sm">
                <Download className="size-3.5" />
                Download {name}
              </Button>
            </a>
          </div>
        )}
      </div>
    </ModalCore>
  );
}
