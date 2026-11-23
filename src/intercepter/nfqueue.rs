use nfq::Queue;

use crate::{
    error::error::IntercepterError,
    intercepter::types::QueueCatcher
};

impl QueueCatcher
{
    pub fn bind(queue_num: u16) -> Result<Self, IntercepterError>
    {
        let mut queue = Queue::open()?;
        
        queue.bind(queue_num)?;
        queue.set_copy_range(queue_num, u16::MAX)?; //get the entire packet
        
        //any overflown packet skip the queue
        //and get shipped straight to the internet
        queue.set_fail_open(queue_num, true)?;
        
        Ok(Self {queue})
    }
}