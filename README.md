# icmp_logging
Логирования пришедших эхо-запросов с исопользованием BCC  
## Установка BCC
https://github.com/AndreiBykov/tcp_filter/blob/master/INSTALL.md  
## Использование
`sudo python icmp_logging.py <if_name> [<filename>]`  
*if_name* - имя сетевого интерфейса для прослушивания (UNIX комадна *ifconfig* - список доступных интерфейсов)  
*filename* - имя файла для записи (опционально)  
Для C++:
```
make
sudo ./icmp_logging <if_name> [<filename>]
```
## Пример использования
Запуск:  
`sudo python icmp_logging.py lo`  
Отправка запросов:  
`ping6 -c 5 ip6-localhost`  
или  
`ping6 -c 5 fe80::9ef6:ebed:8a27:cb89%wlp3s0`  
*fe80::9ef6:ebed:8a27:cb89* - IPv6 (можно просмотреть также в *ifconfig*)  
*wlp3s0* - сетевой интерфейс, которому принадлежит указанный IPv6
