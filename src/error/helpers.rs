use crate::error::error::ConfigError;



pub fn parse_u16(field: &'static str, input: &str) -> Result<u16, ConfigError>
{
    input.parse()
        .map_err(|source| ConfigError::InvalidNumber
            {
                field,
                input: input.to_string(),
                source 
            })
}