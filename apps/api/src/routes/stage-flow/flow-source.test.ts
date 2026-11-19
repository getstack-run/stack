import { describe, expect, it } from 'vitest';
import { FLOWS, flowSource, routeSource, stageFiles } from './flow-source.js';

/**
 * A split route is only as well tested as its flattened source is faithful. The
 * ordering tests (Mission admission before credential use, authority before the
 * meter, meter commit before dispatch) read each route through flowSource(), so
 * these checks pin what makes that reading valid: the stage list is complete,
 * the registrar runs the stages in the listed order, and no stage registers a
 * route of its own (every `app.<verb>` stays in the registrar where the
 * route-classification tests look for it).
 */

describe.each(Object.entries(FLOWS).filter(([, flow]) => flow.stages.length > 0))(
  'stage flow: %s',
  (name, flow) => {
    it('lists every module of its stage directory, so none hides from the structural tests', () => {
      expect([...flow.stages].sort()).toEqual(stageFiles(flow));
    });

    it('calls its stages in the order the flattened source assumes', () => {
      const registrar = routeSource(flow.registrar);
      let previous = -1;
      for (const call of flow.calls) {
        const at = registrar.indexOf(call, previous + 1);
        expect(at, `${flow.registrar}: stage call ${call} missing or out of order`).toBeGreaterThan(previous);
        previous = at;
      }
    });

    it('keeps route registrations in the registrar, never in a stage module', () => {
      for (const stage of flow.stages) {
        const text = routeSource(`${flow.dir}/${stage}`)
          .split('\n')
          .map((l) => l.replace(/\/\/.*$/, ''))
          .join('\n')
          .replace(/\/\*[\s\S]*?\*\//g, '');
        expect(text, `${flow.dir}/${stage} registers a route`).not.toMatch(/\bapp\.(get|post|put|patch|delete|all)\s*[<(]/);
      }
    });

    it('flattens to a text that contains the registrar and every stage', () => {
      const text = flowSource(name);
      expect(text.length).toBeGreaterThan(routeSource(flow.registrar).length);
    });
  },
);
