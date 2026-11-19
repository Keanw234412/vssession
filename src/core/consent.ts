/** Bump when the shared content types change; existing auto-share consent then becomes invalid. */
export const CONTENT_SCHEMA = 1;

export interface AutoConsent {
  /** Workspace folder whose Claude sessions are shared. */
  sourceDir: string;
  root: string;
  orgId: string;
  projectId: string;
  contentSchema: number;
  consentAt: string;
}

export interface WorkspaceLink {
  /** The exact workspace folder that was linked (multi-root order can change). */
  sourceDir: string;
  root: string;
  orgId: string;
  projectId: string;
  projectName: string;
  linkedAt: string;
  auto?: AutoConsent;
}

/** Consent is valid only for the exact destination and content schema it was given for. */
export function autoConsentValid(link: WorkspaceLink | undefined, contentSchema = CONTENT_SCHEMA): boolean {
  const a = link?.auto;
  return !!link && !!a && typeof a.sourceDir === 'string' && a.sourceDir === link.sourceDir && a.root === link.root &&a.orgId === link.orgId && a.projectId === link.projectId && a.contentSchema === contentSchema;
}
