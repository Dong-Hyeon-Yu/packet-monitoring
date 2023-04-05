//
// Created by yudonghyun on 23. 4. 5.
//

#ifndef PCAP_TEMPLATE_SINGLETON_H
#define PCAP_TEMPLATE_SINGLETON_H

#include <memory>

namespace libpacket {

    template < typename T >
    class template_singleton
    {
    protected:
        template_singleton()=default;
        virtual ~template_singleton()=default;
    public:

        static T *  GetInstance()
        {
            if (m_pInstance == NULL)
                m_pInstance = new T;
            return m_pInstance;
        };

        static void DestroyInstance()
        {
            if (m_pInstance)
            {
                delete m_pInstance;
                m_pInstance = NULL;
            }
        };

    private:
        static T * m_pInstance;
    };

    template <typename T> T * template_singleton<T>::m_pInstance = 0;
}


#endif //PCAP_TEMPLATE_SINGLETON_H
