import {readFile} from 'node:fs/promises';
import {parsePrRegistry} from '../registry/pr-contract.mjs';
const body = await readFile(new URL('../registry/prs.json', import.meta.url), 'utf8');
// The registry is a historical record kept under the repository name it was written for. The repository has since
// moved organizations; the record is validated in full against its recorded name, and the check only runs in the
// recorded repository or its one known successor (compared case-insensitively, as GitHub does).
const recorded = JSON.parse(body).repository;
const SUCCESSORS = { 'neophilism/consent-rights-and-use-decisions-engine': 'justice-for-all-movement/consent-rights-and-use-decisions-engine' };
const current = process.env.GITHUB_REPOSITORY;
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
if (current && !same(current, recorded) && !same(current, SUCCESSORS[String(recorded).toLowerCase()]))
  throw new Error('PR registry belongs to a different repository: ' + recorded);
const repository = recorded;
const {document} = parsePrRegistry(body, repository);
const retired = JSON.parse(await readFile(new URL('../registry/roadmap.json', import.meta.url), 'utf8'));
if (retired.repository !== repository || retired.deprecated !== true || retired.redirectTo !== 'registry/prs.json' ||
    Object.hasOwn(retired, 'milestones') || Object.hasOwn(retired, 'units') || Object.hasOwn(retired, 'plannedPrCount'))
  throw new Error('Only registry/prs.json may contain the active PR plan');
console.log(`Valid PR registry: ${repository}, ${document.units.length} approved units; runtime acceptance is separate.`);
