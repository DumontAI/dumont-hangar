/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { observer } from "mobx-react";
// components
import { SettingsBoxedControlItem } from "@/components/settings/boxed-control-item";
import { SettingsHeading } from "@/components/settings/heading";

export const BillingRoot = observer(function BillingRoot() {
  return (
    <section className="relative scrollbar-hide size-full overflow-y-auto">
      <div>
        <SettingsHeading
          title="Plan"
          description="Dumont Hangar is self-hosted on Dumont infrastructure. Every feature is on, for everyone."
        />
        <div className="mt-6">
          <SettingsBoxedControlItem
            title="Dumont Hangar"
            description="Unlimited members, projects, work items, cycles, modules, pages, and storage"
          />
        </div>
      </div>
    </section>
  );
});
