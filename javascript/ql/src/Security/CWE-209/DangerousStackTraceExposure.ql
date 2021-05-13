/**
 * @name Information exposure through a stack trace
 * @description Propagating stack trace information to an external user can
 *              unintentionally reveal implementation details that are useful
 *              to an attacker for developing a subsequent exploit.
 * @kind path-problem
 * @problem.severity warning
 * @precision very-high
 * @id js/dangerous-stack-trace-exposure
 * @tags security
 *       external/cwe/cwe-209
 */

import javascript
import semmle.javascript.security.dataflow.DangerousStackTraceExposure::StackTraceExposure
import DataFlow::PathGraph

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Stack trace information from $@ may be exposed to an external user here.", source.getNode(),
  "here"
