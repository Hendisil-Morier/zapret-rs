use crate::packet::{error::PacketError};

pub struct ByteReader<'a>
{
    data: &'a [u8],
    pos: usize,
}

pub type PEResult<T> = Result<T, PacketError>;

impl<'a> ByteReader<'a>
{
    pub fn new(data: &'a [u8]) -> Self
    {
        Self{ data, pos:0 }
    }
    
    //return the current index
    pub fn pos(&self) -> usize
    {
        self.pos
    }
    
    //borrow the next `len` byte and advance `pos`.
    //return None if something went wrong
    pub fn read_bytes(&mut self, len: usize) -> PEResult<&'a [u8]>
    {
        let end = self.pos.checked_add(len)
                                .ok_or(PacketError::Truncated)?;
        
        let slice =  self.data.get(self.pos..end)
                                .ok_or(PacketError::Truncated)?;
        
        self.pos = end;
        
        Ok(slice)
    }
    
    pub fn read_array<const N: usize>(&mut self)
    -> PEResult<[u8; N]>
    {
        self.read_bytes(N)?
            .try_into() //try turn &[u8] into [u8; N]
            .map_err(|_| PacketError::Truncated)   //swap that error out for a truncated error
    }
    
    //read next 1 byte (u8)
    pub fn read_u8(&mut self) -> PEResult<u8>
    {
        let byte= self.read_bytes(1)?[0];
        
        Ok(byte)
    }
  
    //read next 2 bytes (u16)
    pub fn read_u16(&mut self) -> PEResult<u16>
    {
        let b= self.read_array::<2>()?;

        let two_bytes = u16::from_be_bytes(b);
        
        Ok(two_bytes)
    }
    
    //read next 4 bytes (u32)
    pub fn read_u32(&mut self) -> PEResult<u32>
    {
        let b = self.read_array::<4>()?;
        
        let four_bytes = u32::from_be_bytes(b);
        
        Ok(four_bytes)
    }
    
    pub fn skip(&mut self, len: usize) -> PEResult<()>
    {
        self.read_bytes(len)
            .map(|_| ())
    }
    
    pub fn remaining(&self) -> &'a [u8]
    {
        self.data
            .get(self.pos..)
            .unwrap_or(&[])
    }
    
    /// Shrinks the readable end of the buffer to `max_len`, dropping trailing padding.    
    pub fn truncate(&mut self, max_len: usize) -> PEResult<()>
    {
        if max_len > self.data.len()
        || max_len < self.pos
        {
            return Err(PacketError::Truncated);
        }
        
        self.data = &self.data[..max_len];
        
        return Ok(());
    }
}