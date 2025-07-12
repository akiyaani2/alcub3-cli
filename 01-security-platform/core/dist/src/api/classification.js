/*
 * Copyright 2024 ALCUB3 Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Classification utilities for MAESTRO-aware API routing.
 */
export var ClassificationLevel;
(function (ClassificationLevel) {
    ClassificationLevel["UNCLASSIFIED"] = "UNCLASSIFIED";
    ClassificationLevel["CUI"] = "CUI";
    ClassificationLevel["SECRET"] = "SECRET";
    ClassificationLevel["TOP_SECRET"] = "TOP_SECRET";
})(ClassificationLevel || (ClassificationLevel = {}));
const ORDER = [
    ClassificationLevel.UNCLASSIFIED,
    ClassificationLevel.CUI,
    ClassificationLevel.SECRET,
    ClassificationLevel.TOP_SECRET,
];
/**
 * Returns true if the requester classification level is allowed to access a
 * resource that requires the provided minimum classification level.
 */
export function isClassificationAllowed(requester, required) {
    const reqLevel = (requester || 'UNCLASSIFIED').toUpperCase();
    // Fallback to UNCLASSIFIED for unknown strings
    const requesterLevel = ClassificationLevel[reqLevel] ?? ClassificationLevel.UNCLASSIFIED;
    return ORDER.indexOf(requesterLevel) >= ORDER.indexOf(required);
}
//# sourceMappingURL=classification.js.map