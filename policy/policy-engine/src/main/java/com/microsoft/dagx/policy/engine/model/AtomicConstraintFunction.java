package com.microsoft.dagx.policy.engine.model;

/**
 * An extension point that evaluates an {@link AtomicConstraint}.
 */
@FunctionalInterface
public interface AtomicConstraintFunction<RIGHT_VALUE, RESULT, RULE_TYPE extends Rule> {

    /**
     * Performs the evaluation.
     *
     * @param operator the operation
     * @param rightValue the right-side expression for the constraint
     */
    RESULT evaluate(Operator operator, RIGHT_VALUE rightValue, RULE_TYPE rule);

}
