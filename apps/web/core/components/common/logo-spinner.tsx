/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

// assets
import DumontHangarLogo from "@/app/assets/images/dumont-hangar-logo.png?url";

// Dumont branding: static magenta icon with a pulse instead of the animated Plane GIF.
export function LogoSpinner() {
  return (
    <div className="flex items-center justify-center">
      <img src={DumontHangarLogo} alt="Dumont Hangar" className="h-6 w-auto animate-pulse object-contain sm:h-11" />
    </div>
  );
}
