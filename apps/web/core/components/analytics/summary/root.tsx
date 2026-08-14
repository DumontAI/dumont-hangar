/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import React from "react";
import { useTranslation } from "@plane/i18n";
import { ChartXAxisProperty, ChartYAxisMetric } from "@plane/types";
import AnalyticsSectionWrapper from "../analytics-section-wrapper";
import AnalyticsWrapper from "../analytics-wrapper";
import TotalInsights from "../total-insights";
import PriorityChart from "../work-items/priority-chart";

/**
 * The breakdowns a Jira project summary opens with. Each one is the shared
 * chart with a different x axis, so the project filter in the header applies
 * to all of them: no project selected means the whole workspace.
 */
const BREAKDOWNS = [
  { key: "status_overview", x_axis: ChartXAxisProperty.STATES },
  { key: "priority_breakdown", x_axis: ChartXAxisProperty.PRIORITY },
  { key: "team_workload", x_axis: ChartXAxisProperty.ASSIGNEES },
  { key: "types_of_work", x_axis: ChartXAxisProperty.LABELS },
] as const;

function Summary() {
  const { t } = useTranslation();

  return (
    <AnalyticsWrapper i18nTitle="workspace_analytics.summary.label">
      <div className="flex flex-col gap-14">
        <TotalInsights analyticsType="summary" />
        {BREAKDOWNS.map((breakdown) => (
          <AnalyticsSectionWrapper key={breakdown.key} title={t(`workspace_analytics.summary.${breakdown.key}`)}>
            <PriorityChart x_axis={breakdown.x_axis} y_axis={ChartYAxisMetric.WORK_ITEM_COUNT} />
          </AnalyticsSectionWrapper>
        ))}
      </div>
    </AnalyticsWrapper>
  );
}

export { Summary };
