//! Serde for the types whose persistent form is their textual form.

/// Implement `Serialize`/`Deserialize` through `Display` and `parse`.
///
/// The model is not serialised into a wire format here; it is serialised so that a store can keep
/// it. Keeping the textual spelling — `example.com:443`, a hyphenated UUID — means a file written
/// by SubA stays readable and diffable, and it costs no allocation on the way out
/// (`Serializer::collect_str`).
macro_rules! serde_string {
    ($ty:ty) => {
        impl serde::Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct Text;

                impl<'de> serde::de::Visitor<'de> for Text {
                    type Value = $ty;

                    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        f.write_str(concat!("a ", stringify!($ty), " in its textual form"))
                    }

                    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        // Spelled out rather than `to_string()`: without `std` the method comes from
                        // a trait that is not in scope where this macro expands.
                        <$ty>::parse(value)
                            .map_err(|error| E::custom(alloc::string::ToString::to_string(&error)))
                    }
                }

                deserializer.deserialize_str(Text)
            }
        }
    };
}

pub(crate) use serde_string;
