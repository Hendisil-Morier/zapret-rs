use crate::{
    packet::{
        byte_reader::PEResult,
        types::*
    },
    
    utils::{
        error::PacketError,
        helpers::*
    }
};


pub fn parse_ipv4_header(r: &mut ByteReader<'_>)
-> PEResult<Ipv4Header>
{
    let ver_ihl = r.read_u8()?;
    
    let version = upper_4bits(ver_ihl);
    if version != 4
    {
        return Err(PacketError::UnsupportedVersion(version));
    }
    
    let header_len = lower_4bits(ver_ihl);
    let ip_bytes_len = (header_len as usize) * 4;
    
    if ip_bytes_len < 20
    {
        return Err(PacketError::InvalidHeaderLen(ip_bytes_len));
    }
    
    Ok(Ipv4Header
        {
            version,
            header_len,
            
            tos:        r.read_u8()?,
            total_len:  r.read_u16()?,
            
            id:         r.read_u16()?,
            frag_off:   r.read_u16()?,
            ttl:        r.read_u8()?,
            
            protocol:   r.read_u8()?,
            checksum:   r.read_u16()?,
            
            src:        r.read_array::<4>()?,
            dst:        r.read_array::<4>()?,
            
            options:    r.read_bytes(ip_bytes_len - 20)?.to_vec(),
        })
}

fn parse_tcp_header(reader: &mut ByteReader)
-> PEResult<TcpHeader>
{
    let s_port = reader.read_u16()?;
    let d_port = reader.read_u16()?;
    
    let seq = reader.read_u32()?;
    let ack = reader.read_u32()?;
    
    let off_res = reader.read_u8()?;
    let data_offset = upper_4bits(off_res);
    let reserved = lower_4bits(off_res);
    
    let tcp_bytes_len = (data_offset as usize) * 4;
    if tcp_bytes_len < 20
    {
        return Err(PacketError::InvalidHeaderLen(tcp_bytes_len));
    }
    
    let flags = reader.read_u8()?;
    let window = reader.read_u16()?;
    let checksum = reader.read_u16()?;
    let urgent_ptr = reader.read_u16()?;
    let option_bytes = reader.read_bytes(tcp_bytes_len - 20)?;
    
    Ok(TcpHeader
        {
            s_port,
            d_port,
            seq,
            ack,
            data_offset,
            reserved,
            flags,
            window,
            checksum,
            urgent_ptr,
            options: parse_tcp_option(option_bytes),
        })
}

pub fn parse_ipv4_tcp(raw: &[u8])
-> PEResult<Dissecter>
{
    let mut reader = ByteReader::new(raw);
    
    let ip = parse_ipv4_header(&mut reader)?;
    if ip.protocol != 6
    {
        return Err(PacketError::UnsupportedProtocol(ip.protocol));
    }
    
    let tcp = parse_tcp_header(&mut reader)?;
    let payload = reader.remaining().to_vec();
    
    Ok(Dissecter { ip, tcp, payload })
}

fn parse_tcp_option(input: &[u8]) -> Vec<TcpOption>
{
    unimplemented!();
}