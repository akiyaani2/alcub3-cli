export declare enum ClassificationLevel {
    UNCLASSIFIED = "UNCLASSIFIED",
    CUI = "CUI",
    SECRET = "SECRET",
    TOP_SECRET = "TOP_SECRET"
}
/**
 * Returns true if the requester classification level is allowed to access a
 * resource that requires the provided minimum classification level.
 */
export declare function isClassificationAllowed(requester: string, required: ClassificationLevel): boolean;
