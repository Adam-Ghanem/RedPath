export type Severity = "Critical" | "High" | "Medium" | "Low";

export type GraphNode = {
  id: string;
  label: string;
  subtitle: string;
  kind: "workstation" | "server" | "identity" | "certificate" | "domain";
  severity: Severity;
  x: number;
  y: number;
  status: "observed" | "exposed" | "chokepoint" | "target";
};

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  weight: number;
  label: string;
  technique: string;
};

export type AttackPath = {
  id: string;
  name: string;
  risk: Severity;
  nodeIds: string[];
  edgeIds: string[];
  cost: number;
  summary: string;
  chokepoint: string;
};

export type Finding = {
  id: string;
  asset: string;
  severity: Severity;
  cvss: number;
  technique: string;
  title: string;
  evidence: string;
  remediation: string;
};

export type Scenario = {
  id: string;
  title: string;
  category: string;
  description: string;
  expectedTechniques: string[];
  reconPlan: string[];
  riskSummary: string;
  evidence: string[];
  pathId: string;
  status: "coverage gap" | "partially covered" | "validated";
};

export const graphNodes: GraphNode[] = [
  { id: "WS-21", label: "WS-21", subtitle: "Finance workstation", kind: "workstation", severity: "Medium", x: 12, y: 69, status: "observed" },
  { id: "APP-01", label: "APP-01", subtitle: "Line-of-business server", kind: "server", severity: "High", x: 35, y: 54, status: "exposed" },
  { id: "FS-01", label: "FS-01", subtitle: "File services", kind: "server", severity: "Medium", x: 51, y: 75, status: "observed" },
  { id: "SVC-BACKUP", label: "svc-backup", subtitle: "Service identity", kind: "identity", severity: "Critical", x: 56, y: 31, status: "chokepoint" },
  { id: "CA-01", label: "CA-01", subtitle: "Enterprise CA", kind: "certificate", severity: "Critical", x: 74, y: 45, status: "chokepoint" },
  { id: "ADM-T0", label: "Tier-0 Admins", subtitle: "Privileged group", kind: "identity", severity: "Critical", x: 80, y: 76, status: "target" },
  { id: "DC-01", label: "DC-01", subtitle: "Domain controller", kind: "domain", severity: "Critical", x: 89, y: 17, status: "target" },
];

export const graphEdges: GraphEdge[] = [
  { id: "e1", source: "WS-21", target: "APP-01", weight: 2, label: "Cached admin session", technique: "T1021.002" },
  { id: "e2", source: "APP-01", target: "SVC-BACKUP", weight: 3, label: "Service ticket exposure", technique: "T1558.003" },
  { id: "e3", source: "WS-21", target: "FS-01", weight: 4, label: "Delegated shares", technique: "T1021.002" },
  { id: "e4", source: "FS-01", target: "ADM-T0", weight: 4, label: "Nested privileged group", technique: "T1098" },
  { id: "e5", source: "SVC-BACKUP", target: "CA-01", weight: 2, label: "Certificate enrollment", technique: "T1649" },
  { id: "e6", source: "CA-01", target: "DC-01", weight: 1, label: "Directory replication path", technique: "T1649" },
  { id: "e7", source: "CA-01", target: "ADM-T0", weight: 2, label: "Enrollment agent trust", technique: "T1649" },
  { id: "e8", source: "SVC-BACKUP", target: "DC-01", weight: 3, label: "Legacy delegation", technique: "T1558.004" },
];

export const attackPaths: AttackPath[] = [
  {
    id: "path-service-ticket",
    name: "Service identity to directory control",
    risk: "Critical",
    nodeIds: ["WS-21", "APP-01", "SVC-BACKUP", "DC-01"],
    edgeIds: ["e1", "e2", "e8"],
    cost: 8,
    summary: "A cached administrative session and exposed service ticket form the shortest observed route to directory control.",
    chokepoint: "svc-backup",
  },
  {
    id: "path-certificate",
    name: "Certificate template to Tier-0 access",
    risk: "Critical",
    nodeIds: ["WS-21", "APP-01", "SVC-BACKUP", "CA-01", "ADM-T0"],
    edgeIds: ["e1", "e2", "e5", "e7"],
    cost: 9,
    summary: "The service identity is the dominant chokepoint because it reaches a risky certificate template trusted by Tier-0 groups.",
    chokepoint: "CA-01",
  },
  {
    id: "path-lateral",
    name: "File services blast radius",
    risk: "High",
    nodeIds: ["WS-21", "FS-01", "ADM-T0"],
    edgeIds: ["e3", "e4"],
    cost: 8,
    summary: "Delegated file-share access crosses into a nested privileged group without a monitored review boundary.",
    chokepoint: "FS-01",
  },
];

export const coverageByTactic = [
  { tactic: "Initial Access", detected: 3, expected: 4, percent: 75, color: "#66e3a5" },
  { tactic: "Credential Access", detected: 2, expected: 4, percent: 50, color: "#e8c968" },
  { tactic: "Privilege Esc.", detected: 4, expected: 5, percent: 80, color: "#80b7ff" },
  { tactic: "Lateral Movement", detected: 3, expected: 3, percent: 100, color: "#a68bff" },
];

export const mitreCoverage = [
  { technique: "T1558.003", name: "Kerberoasting", status: "Gap", detail: "Expected in the service-ticket scenario; no correlated alert observed." },
  { technique: "T1558.004", name: "AS-REP Roasting", status: "Partial", detail: "Identity telemetry is present, but the account-attribute change is not enriched." },
  { technique: "T1649", name: "Steal or Forge Authentication Certificates", status: "Gap", detail: "Certificate enrollment events are available; template-risk logic is missing." },
  { technique: "T1021.002", name: "SMB/Windows Admin Shares", status: "Covered", detail: "Observed lateral use is correlated with asset ownership and session context." },
];

export const findings: Finding[] = [
  { id: "RP-101", asset: "SVC-BACKUP", severity: "Critical", cvss: 9.1, technique: "T1558.003", title: "Service account exposes recoverable ticket material", evidence: "Synthetic SPN inventory shows MSSQLSvc binding with unconstrained delegation metadata.", remediation: "Rotate the service credential, remove unconstrained delegation, and enforce AES-only service tickets." },
  { id: "RP-102", asset: "CA-01", severity: "Critical", cvss: 9.0, technique: "T1649", title: "Enrollment template permits subject-supplied identity", evidence: "Synthetic template ESC1-Lab has Client Authentication EKU and Enrollee Supplies Subject enabled.", remediation: "Disable subject supply, restrict enrollment to a managed group, and monitor template modifications." },
  { id: "RP-103", asset: "APP-01", severity: "High", cvss: 8.2, technique: "T1021.002", title: "Privileged session remains reachable from a user segment", evidence: "Synthetic session map reports a local administrator token reachable from WS-21.", remediation: "Remove standing local admin rights, isolate management paths, and require privileged access workstations." },
  { id: "RP-104", asset: "FS-01", severity: "High", cvss: 7.6, technique: "T1098", title: "Nested group membership expands Tier-0 blast radius", evidence: "Synthetic group graph resolves Finance-Operators through two nested groups into a privileged role.", remediation: "Flatten nested privilege, apply time-bound membership, and assign accountable owners for every group." },
  { id: "RP-105", asset: "DC-01", severity: "Medium", cvss: 6.5, technique: "T1558.004", title: "Pre-authentication exception lacks coverage signal", evidence: "Synthetic account inventory reports one pre-authentication-disabled test account without a corresponding detection.", remediation: "Re-enable pre-authentication unless formally exempted and add a rule for account-attribute drift." },
];

export const scenarios: Scenario[] = [
  {
    id: "service-ticket",
    title: "Service identity exposure",
    category: "Credential path",
    description: "Trace a safe, evidence-only path from a low-trust workstation to a service identity with exposed delegation metadata.",
    expectedTechniques: ["T1558.003 Kerberoasting", "T1021.002 SMB/Windows Admin Shares"],
    reconPlan: ["nmap -sV --version-light APP-01.lab.local --dry-run", "ldapsearch -LLL '(servicePrincipalName=*)'  # dry-run: display-only", "bloodhound-python --collectionmethod DCOnly --dry-run"],
    riskSummary: "Critical. The synthetic path reaches svc-backup in two weighted hops, then inherits a legacy delegation route to DC-01.",
    evidence: ["SPN inventory resolves SVC-BACKUP on APP-01", "Delegation flag recorded on the service identity", "No correlated T1558.003 alert in the purple-team evidence set"],
    pathId: "path-service-ticket",
    status: "coverage gap",
  },
  {
    id: "preauth-drift",
    title: "Pre-authentication drift",
    category: "Identity hygiene",
    description: "Review synthetic account controls for a pre-authentication exception and prove whether the defensive signal is usable.",
    expectedTechniques: ["T1558.004 AS-REP Roasting", "T1098 Account Manipulation"],
    reconPlan: ["ldapsearch -LLL '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'  # dry-run: display-only", "Get-ADUser -Filter * -Properties DoesNotRequirePreAuth  # dry-run: display-only", "redpath collect identities --dry-run"],
    riskSummary: "High. A lab account retains a pre-authentication exception; event collection exists but the change is not connected to an owner or detection rule.",
    evidence: ["One synthetic user object has DoesNotRequirePreAuth=true", "Account-change telemetry has no enrichment for accountable team", "Technique coverage is marked Partial"],
    pathId: "path-service-ticket",
    status: "partially covered",
  },
  {
    id: "certificate-escape",
    title: "Certificate template escape",
    category: "AD CS posture",
    description: "Evaluate a safe certificate-template misconfiguration and its relationship to Tier-0 privilege without issuing or using a certificate.",
    expectedTechniques: ["T1649 Steal or Forge Authentication Certificates", "T1098 Account Manipulation"],
    reconPlan: ["certutil -template --dry-run", "certipy find -vulnerable -dc-ip 10.10.10.10 --dry-run", "redpath inspect template ESC1-Lab --dry-run"],
    riskSummary: "Critical. CA-01 is a chokepoint: a risky template creates a low-cost trust edge to Tier-0 Admins and DC-01.",
    evidence: ["ESC1-Lab has Client Authentication EKU", "Enrollee Supplies Subject is enabled in the synthetic template", "No purple-team rule validates template-risk conditions"],
    pathId: "path-certificate",
    status: "coverage gap",
  },
  {
    id: "file-blast-radius",
    title: "File services blast radius",
    category: "Lateral movement",
    description: "Map a synthetic delegated-share relationship into a privileged group and evaluate the containment boundary.",
    expectedTechniques: ["T1021.002 SMB/Windows Admin Shares", "T1098 Account Manipulation"],
    reconPlan: ["smbclient -L //FS-01 --dry-run", "Get-ADGroupMember Finance-Operators -Recursive  # dry-run: display-only", "redpath path resolve WS-21 ADM-T0 --dry-run"],
    riskSummary: "High. FS-01 is an observable chokepoint, but nested-group ownership is unclear and remediation needs a scheduled access review.",
    evidence: ["Synthetic ACL permits Finance-Operators delegated share access", "Group graph reaches ADM-T0 through two nesting levels", "SMB telemetry is correlated and marked Covered"],
    pathId: "path-lateral",
    status: "validated",
  },
];

export function overallCoverage() {
  const detected = coverageByTactic.reduce((total, tactic) => total + tactic.detected, 0);
  const expected = coverageByTactic.reduce((total, tactic) => total + tactic.expected, 0);
  return Math.round((detected / expected) * 100);
}

export function pathById(pathId: string) {
  return attackPaths.find((path) => path.id === pathId) ?? attackPaths[0];
}

export function scenarioHasCompleteDetail(scenario: Scenario) {
  return Boolean(scenario.expectedTechniques.length && scenario.reconPlan.length && scenario.evidence.length && scenario.riskSummary);
}
