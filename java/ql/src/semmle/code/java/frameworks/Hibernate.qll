/**
 * Provides classes and predicates for working with the Hibernate framework.
 */

import java

/** The interface `org.hibernate.query.QueryProducer`. */
class HibernateQueryProducer extends RefType {
  HibernateQueryProducer() { this.hasQualifiedName("org.hibernate.query", "QueryProducer") }
}

/** The interface `org.hibernate.SharedSessionContract`. */
class HibernateSharedSessionContract extends RefType {
  HibernateSharedSessionContract() {
    this.hasQualifiedName("org.hibernate", "SharedSessionContract")
  }
}

/** The interface `org.hibernate.Session`. */
class HibernateSession extends RefType {
  HibernateSession() { this.hasQualifiedName("org.hibernate", "Session") }

  /** Gets a method named `createQuery` declared in the `Session` interface. */
  Method getACreateQueryMethod() {
    result.hasName("createQuery") and
    result = this.getAMethod()
  }

  /** Gets a method named `createNamedQuery` declared in the `Session` interface. */
  Method getACreateNamedQueryMethod() {
    result.hasName("createNamedQuery") and
    result = this.getAMethod()
  }

  /** Gets a method named `createNativeQuery` declared in the `Session` interface. */
  Method getACreateNativeQueryMethod() {
    result.hasName("createNativeQuery") and
    result = this.getAMethod()
  }

  /** Gets a method named `createSQLQuery` declared in the `Session` interface. */
  Method getACreateSQLQueryMethod() {
    result.hasName("createSQLQuery") and
    result = this.getAMethod()
  }
}

/**
 * Holds if `m` is a method on `HibernateQueryProducer`, or `HibernateSharedSessionContract`
 * or `HibernateSession`, or a subclass, taking an SQL string as its first argument.
 */
predicate hibernateSqlMethod(Method m) {
  exists(RefType t |
    t = m.getDeclaringType().getASourceSupertype*() and
    (
      t instanceof HibernateQueryProducer or
      t instanceof HibernateSharedSessionContract or
      t instanceof HibernateSession
    )
  ) and
  m.getParameterType(0) instanceof TypeString and
  m.hasName(["createQuery", "createNativeQuery", "createSQLQuery"])
}
