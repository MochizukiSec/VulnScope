use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            message: Some(message),
            timestamp: chrono::Utc::now(),
        }
    }
}

impl<T> ApiResponse<T> 
where 
    T: Default,
{
    pub fn empty() -> Self {
        Self {
            success: true,
            data: Some(T::default()),
            message: None,
            timestamp: chrono::Utc::now(),
        }
    }
} 