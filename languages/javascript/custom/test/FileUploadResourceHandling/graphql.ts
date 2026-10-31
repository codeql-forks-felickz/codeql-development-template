import depthLimit from 'graphql-depth-limit'
import express from 'express'
import graphqlHTTP from 'express-graphql'
import { createComplexityLimitRule } from 'graphql-validation-complexity'
import costAnalysis from 'graphql-cost-analysis'
import { ApolloServer } from '@apollo/server'
import schema from './schema'

const app = express()

// BAD: only depth limiting; aliases, breadth and overall cost are unbounded.
app.use('/graphql', graphqlHTTP((req, res) => ({
  schema,
  validationRules: [ depthLimit(10) ] // $ Alert
})))

// GOOD: depth and complexity limits.
app.use('/graphql-safe', graphqlHTTP({
  schema,
  validationRules: [ depthLimit(10), createComplexityLimitRule(1000) ]
}))

// BAD: Apollo server with only a depth limit.
export const apollo = new ApolloServer({
  schema,
  validationRules: [ depthLimit(5) ] // $ Alert
})

// GOOD: Apollo server with a cost limit.
export const apolloSafe = new ApolloServer({
  schema,
  validationRules: [ depthLimit(5), costAnalysis({ maximumCost: 1000 }) ]
})

// GOOD: rules are not statically known.
const rules = getRules()
export const apolloDynamic = new ApolloServer({
  schema,
  validationRules: rules
})

declare function getRules(): any[]
