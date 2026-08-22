//! Endpoint/OpenAPI store (port of `src/store/`).

mod openapi_store;

pub use openapi_store::{global, EndpointInfo, OpenApiStore, SecurityInfo};
