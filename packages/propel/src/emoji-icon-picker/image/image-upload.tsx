/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useRef, useState } from "react";
import { ImageUp, Loader2 } from "lucide-react";
import { cn } from "../../utils/classname";

const MAX_SIZE = 2 * 1024 * 1024;

type Props = {
  currentUrl?: string;
  onChange: (url: string) => void;
  /** does the storing and hands back a URL */
  upload: (file: File) => Promise<string>;
};

/** Upload tab of the logo picker: pick a file, get it stored, hand back the URL. */
export function ImageUploadRoot({ currentUrl, onChange, upload }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string>();

  const handleFile = async (file?: File) => {
    if (!file) return;
    if (!file.type.startsWith("image/")) {
      setError("That is not an image.");
      return;
    }
    if (file.size > MAX_SIZE) {
      setError("Keep it under 2 MB.");
      return;
    }
    setError(undefined);
    setIsUploading(true);
    try {
      onChange(await upload(file));
    } catch {
      setError("Upload failed. Try again.");
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="flex flex-col items-center gap-3 p-4">
      {currentUrl && (
        <img src={currentUrl} alt="Current logo" className="size-12 rounded-md object-cover" />
      )}
      <button
        type="button"
        disabled={isUploading}
        onClick={() => inputRef.current?.click()}
        className={cn(
          "flex w-full flex-col items-center gap-2 rounded-md border border-dashed border-strong px-4 py-6",
          "text-13 text-tertiary hover:border-accent-strong hover:text-secondary",
          isUploading && "cursor-wait opacity-60"
        )}
      >
        {isUploading ? <Loader2 className="size-5 animate-spin" /> : <ImageUp className="size-5" />}
        {isUploading ? "Uploading…" : "Choose an image"}
        <span className="text-11 text-placeholder">PNG, JPG or SVG up to 2 MB</span>
      </button>
      {error && <p className="text-11 text-danger-primary">{error}</p>}
      <input
        ref={inputRef}
        type="file"
        accept="image/*"
        hidden
        onChange={(e) => {
          void handleFile(e.target.files?.[0]);
          e.target.value = "";
        }}
      />
    </div>
  );
}
