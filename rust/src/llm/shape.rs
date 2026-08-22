//! Normalized shape trees for schema fingerprinting (W4).
//!
//! A [`Shape`] is the types-only projection of a JSON value: every scalar
//! collapses to its type tag, objects keep their (sorted) keys, and arrays
//! collapse to the **union** of their element shapes. Rendering the tree
//! through [`crate::json::stable_stringify`] gives a byte-stable canonical
//! string, so the sha256 of that rendering ([`super::schema_fp`]) is stable
//! across runs, platforms, and key/whitespace permutations of the input.

use std::collections::BTreeMap;

use serde_json::Value;

/// Types-only normalized shape of a JSON value.
///
/// Derives `Ord` so unions can be sorted/deduped deterministically; ordering
/// is never observable except through the canonical rendering, which sorts
/// again anyway.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Shape {
    Null,
    Bool,
    Num,
    Str,
    /// Element-union of an array: the sorted, deduplicated set of DISTINCT
    /// element shapes. Homogeneous arrays collapse to one element shape
    /// (`[1,2]` -> `[0]`); heterogeneous ones keep one entry per distinct
    /// shape, so the union is order-independent and associative
    /// (`[{"a":1},{"b":"x"}]` -> `[{"a":0},{"b":""}]`).
    Array(Box<[Shape]>),
    Object(BTreeMap<String, Shape>),
}

/// Compute the normalized shape of a JSON value.
pub fn shape_of(value: &Value) -> Shape {
    match value {
        Value::Null => Shape::Null,
        Value::Bool(_) => Shape::Bool,
        Value::Number(_) => Shape::Num,
        Value::String(_) => Shape::Str,
        Value::Array(items) => {
            let mut union: Vec<Shape> = items.iter().map(shape_of).collect();
            // Sorted + deduped: permutation/duplication of elements cannot
            // change the union.
            union.sort();
            union.dedup();
            Shape::Array(union.into_boxed_slice())
        }
        Value::Object(map) => Shape::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), shape_of(v)))
                .collect::<BTreeMap<_, _>>(),
        ),
    }
}

impl Shape {
    /// Canonical `serde_json::Value` projection used for rendering:
    /// Null -> `null`, Bool -> `true`, Num -> `0`, Str -> `""`, arrays to the
    /// array of member projections, objects recursively.
    pub fn to_value(&self) -> Value {
        match self {
            Shape::Null => Value::Null,
            Shape::Bool => Value::Bool(true),
            Shape::Num => Value::Number(serde_json::Number::from(0)),
            Shape::Str => Value::String(String::new()),
            Shape::Array(elems) => Value::Array(elems.iter().map(Shape::to_value).collect()),
            Shape::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), v.to_value()))
                    .collect::<serde_json::Map<String, Value>>(),
            ),
        }
    }

    /// Byte-stable canonical rendering (keys sorted at every depth, compact).
    pub fn render(&self) -> String {
        crate::json::stable_stringify(&self.to_value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scalars_collapse_to_type_tags() {
        assert_eq!(shape_of(&Value::Null), Shape::Null);
        assert_eq!(shape_of(&json!(true)), Shape::Bool);
        assert_eq!(shape_of(&json!(1)), Shape::Num);
        assert_eq!(shape_of(&json!(1.5)), Shape::Num);
        assert_eq!(shape_of(&json!("x")), Shape::Str);
    }

    #[test]
    fn same_tree_different_key_order_and_whitespace_same_render() {
        let a = json!({"b": 1, "a": {"y": [1], "x": null}});
        let b: Value = serde_json::from_str(
            r#"{
                "a" : { "x" : null,  "y": [ 1 ] },
                   "b":1
            }"#,
        )
        .unwrap();
        assert_eq!(shape_of(&a).render(), shape_of(&b).render());
    }

    #[test]
    fn number_formatting_does_not_leak() {
        let a: Value = serde_json::from_str("1").unwrap();
        let b: Value = serde_json::from_str("1.0").unwrap();
        assert_eq!(shape_of(&a).render(), shape_of(&b).render());
    }

    #[test]
    fn homogeneous_arrays_collapse_to_single_element() {
        assert_eq!(
            shape_of(&json!([1, 2, 3])).render(),
            shape_of(&json!([9])).render()
        );
        // Empty arrays render as the empty union; deep nesting still
        // collapses to a single element shape.
        assert_eq!(shape_of(&json!([])).render(), "[]");
        assert_eq!(shape_of(&json!([[[1]]])).render(), "[[[0]]]");
    }

    #[test]
    fn array_permutation_and_duplication_stable() {
        let mixed = shape_of(&json!([{"a": 1}, {"b": "x"}, {"a": true}]));
        let permuted = shape_of(&json!([{"a": true}, {"b": "x"}, {"a": 1}]));
        let duplicated = shape_of(&json!([{"a": 1}, {"a": 1}, {"b": "x"}, {"a": true}]));
        assert_eq!(mixed.render(), permuted.render());
        assert_eq!(mixed.render(), duplicated.render());
    }

    #[test]
    fn heterogeneous_scalars_keep_distinct_union_members_sorted() {
        let shape = shape_of(&json!(["s", 1]));
        let expected = shape_of(&json!([1, "s"]));
        assert_eq!(shape, expected);
        match shape {
            Shape::Array(elems) => {
                assert_eq!(elems.len(), 2);
                assert_eq!(elems.as_ref(), [Shape::Num, Shape::Str]);
            }
            other => panic!("expected array union, got {other:?}"),
        }
    }

    #[test]
    fn object_union_members_stay_distinct_and_sorted() {
        // Distinct element shapes are preserved as separate sorted members;
        // the union is order-independent but never invents merged objects.
        let shape = shape_of(&json!([{"a": {"x": "s", "y": 2}}, {"a": {"x": 1}}]));
        assert_eq!(shape.render(), r#"[{"a":{"x":0}},{"a":{"x":"","y":0}}]"#);
        let permuted = shape_of(&json!([{"a": {"x": 1}}, {"a": {"x": "s", "y": 2}}]));
        assert_eq!(shape, permuted);
    }
}
