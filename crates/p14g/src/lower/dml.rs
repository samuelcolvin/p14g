use sqlparser::ast as sp;

use super::{Lower, query::table, reject, single_name};
use crate::{
    ast::{Assignment, Delete, Expr, Insert, Table, TableFactor, TableWithJoins, Update},
    error::{Error, Result},
};

impl Lower<'_> {
    pub(super) fn insert(&mut self, insert: sp::Insert) -> Result<Insert> {
        let sp::Insert {
            insert_token: _,
            optimizer_hints,
            or,
            ignore,
            into: _,
            table: target,
            table_alias,
            columns,
            by_name,
            overwrite,
            source,
            assignments,
            partitioned,
            after_columns,
            overriding,
            has_table_keyword,
            on,
            returning,
            output,
            replace_into,
            priority,
            insert_alias,
            settings,
            format_clause,
            multi_table_insert_type,
            multi_table_into_clauses,
            multi_table_when_clauses,
            multi_table_else_clause,
        } = insert;
        reject(&optimizer_hints, "an optimizer hint")?;
        reject(&or, "INSERT OR ...")?;
        reject(&ignore, "INSERT IGNORE")?;
        reject(&table_alias, "an alias on the INSERT target")?;
        reject(&by_name, "INSERT BY NAME")?;
        reject(&overwrite, "INSERT OVERWRITE")?;
        reject(&assignments, "INSERT ... SET")?;
        reject(&partitioned, "PARTITION")?;
        reject(&after_columns, "PARTITION")?;
        reject(&overriding, "OVERRIDING")?;
        reject(&has_table_keyword, "INSERT INTO TABLE")?;
        reject(&on, "ON CONFLICT")?;
        reject(&output, "OUTPUT")?;
        reject(&replace_into, "REPLACE INTO")?;
        reject(&priority, "an INSERT priority")?;
        reject(&insert_alias, "an INSERT row alias")?;
        reject(&settings, "SETTINGS")?;
        reject(&format_clause, "FORMAT")?;
        reject(&multi_table_insert_type, "a multi-table INSERT")?;
        reject(&multi_table_into_clauses, "a multi-table INSERT")?;
        reject(&multi_table_when_clauses, "a multi-table INSERT")?;
        reject(&multi_table_else_clause, "a multi-table INSERT")?;

        let table = match target {
            sp::TableObject::TableName(name) => table(name, None)?,
            sp::TableObject::TableFunction(_) | sp::TableObject::TableQuery(_) => {
                return Err(Error::unsupported("INSERT into anything but a table"));
            }
        };
        if columns.is_empty() {
            return Err(Error::unsupported("INSERT without a column list"));
        }
        let columns = columns
            .into_iter()
            .map(|c| single_name(c, "an INSERT column"))
            .collect::<Result<Vec<_>>>()?;

        let Some(source) = source else {
            return Err(Error::unsupported("INSERT ... DEFAULT VALUES"));
        };
        let rows = self.insert_rows(*source)?;
        for row in &rows {
            if row.len() != columns.len() {
                return Err(Error::unsupported(format!(
                    "an INSERT row with {} values for {} columns",
                    row.len(),
                    columns.len()
                )));
            }
        }
        let returning = self.select_items(returning.unwrap_or_default(), "RETURNING")?;
        Ok(Insert {
            table,
            columns,
            rows,
            returning,
        })
    }

    /// The source of an `INSERT` has to be a plain `VALUES` list.
    fn insert_rows(&mut self, source: sp::Query) -> Result<Vec<Vec<Expr>>> {
        let sp::Query {
            with,
            body,
            order_by,
            limit_clause,
            fetch,
            locks,
            for_clause,
            settings,
            format_clause,
            pipe_operators,
        } = source;
        let plain = with.is_none()
            && order_by.is_none()
            && limit_clause.is_none()
            && fetch.is_none()
            && locks.is_empty()
            && for_clause.is_none()
            && settings.is_none()
            && format_clause.is_none()
            && pipe_operators.is_empty();
        let sp::SetExpr::Values(sp::Values {
            explicit_row,
            value_keyword: _,
            rows,
        }) = *body
        else {
            return Err(Error::unsupported("INSERT ... SELECT (only INSERT ... VALUES)"));
        };
        if !plain {
            return Err(Error::unsupported("a clause after INSERT ... VALUES"));
        }
        reject(&explicit_row, "VALUES ROW(...)")?;
        if rows.len() > self.limits.max_values_rows {
            return Err(Error::limit(format!(
                "INSERT has more than {} rows",
                self.limits.max_values_rows
            )));
        }
        rows.into_iter()
            .map(
                |sp::Parens {
                     opening_token: _,
                     content,
                     closing_token: _,
                 }| content.into_iter().map(|e| self.expr(e)).collect(),
            )
            .collect()
    }

    pub(super) fn update(&mut self, update: sp::Update) -> Result<Update> {
        let sp::Update {
            update_token: _,
            optimizer_hints,
            table: target,
            on_cluster,
            assignments,
            from,
            selection,
            returning,
            output,
            or,
            order_by,
            limit,
            settings,
        } = update;
        reject(&optimizer_hints, "an optimizer hint")?;
        reject(&on_cluster, "ON CLUSTER")?;
        reject(&from, "UPDATE ... FROM")?;
        reject(&output, "OUTPUT")?;
        reject(&or, "UPDATE OR ...")?;
        reject(&order_by, "ORDER BY on UPDATE")?;
        reject(&limit, "LIMIT on UPDATE")?;
        reject(&settings, "SETTINGS")?;

        let table = self.write_target(target, "UPDATE")?;
        let assignments = assignments
            .into_iter()
            .map(|sp::Assignment { target, value }| {
                let column = match target {
                    sp::AssignmentTarget::ColumnName(name) => single_name(name, "an UPDATE column")?,
                    sp::AssignmentTarget::Tuple(_) => return Err(Error::unsupported("a tuple assignment")),
                };
                Ok(Assignment {
                    column,
                    value: self.expr(value)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if assignments.is_empty() {
            return Err(Error::unsupported("UPDATE without assignments"));
        }
        Ok(Update {
            table,
            assignments,
            selection: selection.map(|e| self.expr(e)).transpose()?,
            returning: self.select_items(returning.unwrap_or_default(), "RETURNING")?,
        })
    }

    pub(super) fn delete(&mut self, delete: sp::Delete) -> Result<Delete> {
        let sp::Delete {
            delete_token: _,
            optimizer_hints,
            tables,
            from,
            on_cluster,
            using,
            selection,
            returning,
            output,
            order_by,
            limit,
            settings,
        } = delete;
        reject(&optimizer_hints, "an optimizer hint")?;
        reject(&tables, "a multi-table DELETE")?;
        reject(&on_cluster, "ON CLUSTER")?;
        reject(&using, "DELETE ... USING")?;
        reject(&output, "OUTPUT")?;
        reject(&order_by, "ORDER BY on DELETE")?;
        reject(&limit, "LIMIT on DELETE")?;
        reject(&settings, "SETTINGS")?;

        let (sp::FromTable::WithFromKeyword(mut from) | sp::FromTable::WithoutKeyword(mut from)) = from;
        let (Some(target), true) = (from.pop(), from.is_empty()) else {
            return Err(Error::unsupported("DELETE from several tables"));
        };
        Ok(Delete {
            table: self.write_target(target, "DELETE")?,
            selection: selection.map(|e| self.expr(e)).transpose()?,
            returning: self.select_items(returning.unwrap_or_default(), "RETURNING")?,
        })
    }

    /// The target of an `UPDATE` or `DELETE`: one plain table, optionally aliased.
    fn write_target(&mut self, target: sp::TableWithJoins, statement: &str) -> Result<Table> {
        let TableWithJoins { relation, joins } = self.table_with_joins(target)?;
        match (relation, joins.is_empty()) {
            (TableFactor::Table(table), true) => Ok(table),
            _ => Err(Error::unsupported(format!(
                "{statement} of anything but a single table"
            ))),
        }
    }
}
