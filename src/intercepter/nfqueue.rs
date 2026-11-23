use nfq::Queue;

use crate::{
    utils::error::IntercepterError, intercepter::types::{Decision, QueueCatcher}
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
    
    pub fn run<F>(&mut self, mut on_packet: F) -> Result<(), IntercepterError>
    where
        F: FnMut(&[u8], u32) -> Decision
    {
        loop
        {
            let mut msg = self.queue.recv()?;
            
            let decision = on_packet(msg.get_payload(), msg.get_nfmark());
            
            match decision
            {
                Decision::Drop => msg.set_verdict(nfq::Verdict::Drop),
                Decision::Pass => msg.set_verdict(nfq::Verdict::Accept),
                
                Decision::Replace(new_byte) => {
                    msg.set_payload(new_byte);
                    msg.set_verdict(nfq::Verdict::Accept);
                }
            }
            
            self.queue.verdict(msg)?
        }
    }
}