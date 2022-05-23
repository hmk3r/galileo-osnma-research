from osnma import OSNMA

class OSNMA_Storage:
    def __init__(self) -> None:
        self.DSMs = dict()
        self.osnma_messages = dict()
    
    def add(self, osnma_message: OSNMA) -> None:
        if osnma_message.DSM_ID not in self.DSMs:
            self.DSMs[osnma_message.DSM_ID] = {
                'header': None,
                'DSMs': [None] * 21,
                'complete': False
            }
            self.osnma_messages[osnma_message.DSM_ID] = list()
        
        self.osnma_messages[osnma_message.DSM_ID].append(osnma_message)

        if osnma_message.DSM_block_ID == 0 and self.DSMs[osnma_message.DSM_ID]['header'] == None:
            self.DSMs[osnma_message.DSM_ID]['header'] = osnma_message
            self.DSMs[osnma_message.DSM_ID]['DSMs'] = self.DSMs[osnma_message.DSM_ID]['DSMs'][:self.DSMs[osnma_message.DSM_ID]['header'].NB]
        
        if self.DSMs[osnma_message.DSM_ID]['DSMs'][osnma_message.DSM_block_ID] == None:
            self.DSMs[osnma_message.DSM_ID]['DSMs'][osnma_message.DSM_block_ID] = osnma_message._hk_root_str[16:]
        
        if self.DSMs[osnma_message.DSM_ID]['header'] is not None:
            if all(self.DSMs[osnma_message.DSM_ID]['DSMs'][:self.DSMs[osnma_message.DSM_ID]['header'].NB]):
                self.DSMs[osnma_message.DSM_ID]['complete'] = True
            
    def get_all(self, completed=True):
        for key, value in self.DSMs.items():
            if not completed:
                yield key, value
            elif completed and value['complete']:
                yield key, value

    def __repr__(self) -> str:
        return str(self.DSMs)
