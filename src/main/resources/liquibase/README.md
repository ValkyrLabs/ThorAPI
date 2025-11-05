### Notes

databaseChangeLog:
- preConditions:
- runningAs:
    username:  liquibase

- changeSet:
    id:  1
    author:  your.name
    labels: example-label
    context: example-context
    comment: example-comment
    changes:
    - createTable:
    tableName:  person
    columns:
    - column:
    name:  id
    type:  int
    autoIncrement:  true
    constraints:
    primaryKey:  true
    nullable:  false
    - column:
    name:  name
    type:  varchar(50)
    constraints:
    nullable:  false
    - column:
    name:  address1
    type:  varchar(50)
    - column:
    name:  address2
    type:  varchar(50)
    - column:
    name:  city
    type:  varchar(30)


