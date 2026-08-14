/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

/**
 * Multi-select on work item layouts. Upstream ships the selection code but keeps
 * this switch off in the community build; the actions behind it live in
 * components/issues/bulk-operations.
 */
export const useBulkOperationStatus = () => true;
