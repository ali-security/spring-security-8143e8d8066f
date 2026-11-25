/*
 * Copyright 2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.util;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.expression.AccessException;
import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.Expression;
import org.springframework.expression.MethodExecutor;
import org.springframework.expression.MethodFilter;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.TypedValue;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.ReflectiveMethodResolver;
import org.springframework.expression.spel.support.ReflectivePropertyAccessor;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;

/**
 * A RequestMatcher implementation which uses a SpEL expression
 *
 * <p>With the default EvalutationContext ({@link ELRequestMatcherContext}) you can use
 * <code>hasIpAdress()</code> and <code>hasHeader()</code></p>
 *
 * <p>See {@link DelegatingAuthenticationEntryPoint} for a example configuration.</p>
 *
 *
 * @author Mike Wiesner
 * @since 3.0.2
 */
public class ELRequestMatcher implements RequestMatcher {

    private Expression expression;

    public ELRequestMatcher(String el) {
        SpelExpressionParser parser = new SpelExpressionParser();
        expression = parser.parseExpression(el);
    }

    public boolean matches(HttpServletRequest request) {
        EvaluationContext context = createELContext(request);
        return evaluateAsBoolean(expression, context);
    }

    /**
     * Subclasses can override this methode if they want to use a different EL root context
     *
     * <p>The default context only supports read-only data binding with instance methods: type references,
     * constructor invocations, static methods, methods declared on {@link Object} or {@link Class}, property
     * writes and access to {@link Class} or {@link ClassLoader} instances are rejected.</p>
     *
     * @return EL root context which is used to evaluate the expression
     */
    public EvaluationContext createELContext(HttpServletRequest request) {
        StandardEvaluationContext context = new StandardEvaluationContext(new ELRequestMatcherContext(request));
        context.setTypeLocator(new NoTypeLocator());
        context.setConstructorResolvers(new ArrayList<ConstructorResolver>());
        List<MethodResolver> methodResolvers = new ArrayList<MethodResolver>();
        methodResolvers.add(InstanceMethodResolver.create());
        context.setMethodResolvers(methodResolvers);
        List<PropertyAccessor> propertyAccessors = new ArrayList<PropertyAccessor>();
        propertyAccessors.add(new ReadOnlyPropertyAccessor());
        context.setPropertyAccessors(propertyAccessors);
        return context;
    }

    private boolean evaluateAsBoolean(Expression expr, EvaluationContext ctx) {
        try {
            return ((Boolean) expr.getValue(ctx, Boolean.class)).booleanValue();
        } catch (EvaluationException e) {
            throw new IllegalArgumentException("Failed to evaluate expression '" + expr.getExpressionString() + "'", e);
        }
    }

    /**
     * Class and ClassLoader instances give access to arbitrary types, so they must never be used as the target
     * of a method invocation or property read.
     */
    private static boolean isRestrictedTarget(Object target) {
        return target instanceof Class || target instanceof ClassLoader;
    }

    /**
     * Rejects all type references (<code>T(...)</code>).
     */
    private static final class NoTypeLocator implements TypeLocator {

        public Class<?> findType(String typeName) throws EvaluationException {
            throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
        }
    }

    /**
     * Resolves instance methods only: static methods, methods declared on {@link Object} or {@link Class} and
     * methods of {@link Class} or {@link ClassLoader} targets are not resolved.
     * <p>
     * The arguments of {@link MethodResolver}'s <code>resolve</code> method differ between Spring 3.0.x releases,
     * so the resolver is exposed as a JDK proxy that passes the call on to a {@link ReflectiveMethodResolver}.
     */
    private static final class InstanceMethodResolver implements InvocationHandler, MethodFilter {

        private final ReflectiveMethodResolver delegate = new ReflectiveMethodResolver();

        static MethodResolver create() {
            return (MethodResolver) Proxy.newProxyInstance(MethodResolver.class.getClassLoader(),
                    new Class<?>[] {MethodResolver.class}, new InstanceMethodResolver());
        }

        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (method.getDeclaringClass() == Object.class) {
                if ("equals".equals(method.getName())) {
                    return Boolean.valueOf(proxy == args[0]);
                }
                if ("hashCode".equals(method.getName())) {
                    return Integer.valueOf(System.identityHashCode(proxy));
                }
                return InstanceMethodResolver.class.getName();
            }
            // resolve(EvaluationContext context, Object targetObject, String name, argumentTypes)
            Object targetObject = args[1];
            if (targetObject == null || isRestrictedTarget(targetObject)) {
                return null;
            }
            delegate.registerMethodFilter(targetObject.getClass(), this);
            MethodExecutor executor;
            try {
                executor = (MethodExecutor) method.invoke(delegate, args);
            } catch (InvocationTargetException e) {
                throw e.getTargetException();
            }
            return (executor != null ? new InstanceMethodExecutor(executor) : null);
        }

        public List<Method> filter(List<Method> methods) {
            List<Method> instanceMethods = new ArrayList<Method>(methods.size());
            for (Method method : methods) {
                Class<?> declaringClass = method.getDeclaringClass();
                if (!Modifier.isStatic(method.getModifiers()) && declaringClass != Object.class
                        && declaringClass != Class.class) {
                    instanceMethods.add(method);
                }
            }
            return instanceMethods;
        }
    }

    /**
     * Re-checks the target, as SpEL reuses a resolved method for later evaluations of the same expression.
     */
    private static final class InstanceMethodExecutor implements MethodExecutor {

        private final MethodExecutor delegate;

        InstanceMethodExecutor(MethodExecutor delegate) {
            this.delegate = delegate;
        }

        public TypedValue execute(EvaluationContext context, Object target, Object... arguments)
                throws AccessException {
            if (isRestrictedTarget(target)) {
                throw new AccessException("Method invocation on '" + target + "' is not permitted");
            }
            return delegate.execute(context, target, arguments);
        }
    }

    /**
     * Read-only {@link ReflectivePropertyAccessor} which does not expose the <code>class</code> property, nor
     * properties of {@link Class} or {@link ClassLoader} targets.
     */
    private static final class ReadOnlyPropertyAccessor extends ReflectivePropertyAccessor {

        @Override
        public boolean canRead(EvaluationContext context, Object target, String name) throws AccessException {
            return isReadable(target, name) && super.canRead(context, target, name);
        }

        @Override
        public TypedValue read(EvaluationContext context, Object target, String name) throws AccessException {
            if (!isReadable(target, name)) {
                throw new AccessException("Property '" + name + "' cannot be read");
            }
            return super.read(context, target, name);
        }

        @Override
        public boolean canWrite(EvaluationContext context, Object target, String name) {
            return false;
        }

        @Override
        public void write(EvaluationContext context, Object target, String name, Object newValue)
                throws AccessException {
            throw new AccessException("Property '" + name + "' cannot be written");
        }

        /**
         * Keeps every read going through {@link #read}, so that the target is checked on each evaluation.
         */
        @Override
        public PropertyAccessor createOptimalAccessor(EvaluationContext context, Object target, String name) {
            return this;
        }

        private static boolean isReadable(Object target, String name) {
            return !isRestrictedTarget(target) && !"class".equalsIgnoreCase(name);
        }
    }
}
