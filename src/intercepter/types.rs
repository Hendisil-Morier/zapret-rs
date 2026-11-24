//telling what the os should do with this packet
pub enum Decision
{
    Pass,               //let it go
    Drop,               //banish it
    Replace(Vec<u8>),   //replace it with these specified bytes, then let go
}
