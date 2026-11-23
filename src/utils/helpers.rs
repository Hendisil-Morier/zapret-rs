use crate::utils::error::ConfigError;

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

pub fn upper_4bits(input: u8) -> u8
{
    input >> 4
}

pub fn lower_4bits(input: u8) -> u8
{
    input & 0x0F
}