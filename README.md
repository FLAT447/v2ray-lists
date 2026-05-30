# Бесплатные VPN-конфигурации и MTProxy
[![Stars](https://img.shields.io/github/stars/FLAT447/v2ray-lists?style=flat)](https://github.com/FLAT447/v2ray-lists/stargazers) 
<img src="https://komarev.com/ghpvc/?username=FLAT447&label=Visitors&color=0e75b6&style=flat" alt="Visitor Count" /> 
[![Issues](https://img.shields.io/github/issues/FLAT447/v2ray-lists?style=flat&color=0e75b6)](https://github.com/FLAT447/v2ray-lists/issues) 
[![Email](https://img.shields.io/badge/Email-flat447%40proton.me-0e75b6?logo=gmail&logoColor=white)](mailto:flat447@proton.me) 
[![GPL-3.0 License](https://img.shields.io/badge/License-GPL--3.0-blue?style=flat)](./LICENSE) 
[![Website|137](https://img.shields.io/badge/Website-V2Ray%20Lists%20Site-blue?style=flat)](https://flat447.github.io/v2ray-lists-site/) 

Коллекция бесплатных VPN конфигураций (`V2Ray`, `VLESS`, `VMess`, `ShadowSocks`, `Trojan`, `TUIC`, `Hysteria2`, `Reality`) и MTProxy

## 📑 Содержание
- [📑 Содержание](#-содержание)
- [🚀 Быстрый старт](#-быстрый-старт)
- [📊 Статус конфигов](#-статус-конфигов)
- [🗂 Структура репозитория](#-структура-репозитория)
- [🔧 Локальный запуск генератора](#-локальный-запуск-генератора)
- [🗂️ Основные подписки]( #-основные-подписки)
- [🗂️ Общее меню гайдов репозитория](#️-общее-меню-гайдов-репозитория)
- [📜 Лицензия](#-лицензия)

---
## 🚀 Быстрый старт
## VPN:
1. Скопируйте нужную ссылку из раздела **[🗂️ Основные подписки]( #-основные-подписки)**
2. Импортируйте её в ваш **VPN-клиент** (смотрите инструкции ниже)
3. Выберите сервер с наименьшим пингом и подключайтесь
## MTProxy:
1. Заходим на [сайт V2Ray Lists](https://flat447.github.io/v2ray-lists-site/mtproxy/)
2. Жмём __10 случайных__ из __WhiteList__ и заходим в Telegram
3. На мобилках идём по пути `Настройки > Данные и память > Настройки прокси > Три точки > Импорт из буфера обмена` 
4. На ПК идём по пути `Настройки > Продвинутые настройки > Тип соединения > Три точки > Добавить прокси из буфера обмена`


---


# 📊 Статус конфигов

> Не копируйте ссылки отсюда, здесь указаны только источники. Берите конфигурации из раздела **Основные подписки**

| Файл                                                                                                     | Описание                                                                                                                                                              |
| -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
[`BLACK_LTE.txt`](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/BLACK_LTE.txt) | [Подписка для Чёрных Списков, сокращённый список](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/BLACK_LTE.txt)                                             |
[`BLACK_FULL`](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/BLACK_FULL.txt) | [Подписка для Чёрных Списков, полный список](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/BLACK_FULL.txt)                                             |
[`WHITE_FULL.txt`](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/WHITE_FULL.txt) | [Подписка для Белых Списков, полный список](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/WHITE_FULL.txt)                                             |
[`WHITE_LITE.txt`](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/WHITE_LITE.txt) | [Подписка для Белых Списков, сокращённый список](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/WHITE_LITE.txt)                                             |
[`whitelist.txt`](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/whitelist.txt) | [Списки MTProxy для Белых Списков](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/whitelist.txt)                                             |
[`blacklist.txt`](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/blacklist.txt) | [Списки MTProxy для Чёрных списков](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/blacklist.txt)                                            |


---
## 🗂 Структура репозитория
```text
githubmirror/        — сгенерированные .txt конфиги (26 файлов)
qr-codes/            — PNG-версии конфигов для импорта по QR
sources/              — Python-скрипты и зависимости генератора
 ├─ main.py
 ├─ requirements.txt
 └─ proxy_checker.py
.github/workflows/   — CI/CD (авто-обновление каждые 9 мин)
whitelist.txt               — MTProxy для Белых Списков
blacklist.txt               — MTProxy для Чёрных Списков
README.md            — этот файл
```

---
## 🔧 Локальный запуск генератора
```bash
git clone https://github.com/FLAT447/v2ray-lists
cd v2ray-lists/sources
python -m pip install -r requirements.txt
export MY_TOKEN=<GITHUB_TOKEN>   # токен с правом repo, чтобы пушить изменения
python main.py                  # конфиги появятся в ../githubmirror
python proxy_checker                # генерирует файлы whitelist.txt и blacklist.txt
```

---

# 🗂️ Основные подписки

> Рекомендованные списки: **[1](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/1.txt)**, **[6](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/6.txt)**, **[22](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/22.txt)**, **[23](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/23.txt)**, **[24](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/24.txt)** и **[25](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/25.txt)**.

> Обход SNI/CIDR белых списков: **[26](https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/26.txt)** 

1. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/1.txt`
2. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/2.txt`
3. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/3.txt`
4. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/4.txt`
5. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/5.txt`
6. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/6.txt`
7. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/7.txt`
8. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/8.txt`
9. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/9.txt`
10. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/10.txt`
11. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/11.txt`
12. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/12.txt`
13. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/13.txt`
14. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/14.txt`
15. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/15.txt`
16. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/16.txt`
17. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/17.txt`
18. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/18.txt`
19. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/19.txt`
20. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/20.txt`
21. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/21.txt`
22. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/22.txt`
23. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/23.txt`
24. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/24.txt`
25. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/25.txt`
26. `https://github.com/FLAT447/v2ray-lists/raw/refs/heads/main/githubmirror/26.txt`

---
# 🗂️ Общее меню гайдов репозитория
<details>
<summary>Гайд на Andorid</summary>
	
**1.** Скачиваем **«v2rayNG»** — [Ссылка](https://github.com/2dust/v2rayNG/releases/download/2.2.1/v2rayNG_2.2.1_universal.apk)

**2.** Копируем в буфер обмена ссылку из раздела [🗂️ Основные подписки](#-основные-подписки)

**3.** Заходим в приложение **«v2rayNG»** и в правом верхнем углу нажимаем на ➕, а затем выбираем **«Импорт из буфера обмена»**.
   
**4.** Нажимаем **«справа сверху на три точки»**, а затем **«Проверить задержку профилей»**, после окончания проверки в этом же меню нажмите на **«Сортировать по результатам теста»**. 

**5.** Выбираем нужный вам сервер и затем нажимаем на кнопку ▶️ в правом нижнем углу.
</details>
<details>

<summary>Гайд для Android TV</summary>

**1.** Скачиваем **«v2rayNG»** — [Ссылка](https://github.com/2dust/v2rayNG/releases/download/2.2.1/v2rayNG_2.2.1_universal.apk)

> Рекомендованные **«QR-коды»**: **[1](https://github.com/FLAT447/v2ray-lists/blob/main/qr-codes/1.png)**, **[6](https://github.com/FLAT447/v2ray-lists/blob/main/qr-codes/6.png)**, **[22](https://github.com/FLAT447/v2ray-lists/blob/main/qr-codes/22.png)**, **[23](https://github.com/FLAT447/v2ray-lists/blob/main/qr-codes/23.png)**, **[24](https://github.com/FLAT447/v2ray-lists/blob/main/qr-codes/24.png)** и **[25](https://github.com/FLAT447/v2ray-lists/blob/main/qr-codes/25.png)**.

> Обход SNI/CIDR белых списков: **[26](https://github.com/FLAT447/v2ray-lists/blob/main/qr-codes/26.png)**

**2.** Скачиваем **«QR-коды»** — [Ссылка](https://github.com/FLAT447/v2ray-lists/tree/main/qr-codes)

**3**. Заходим в приложение **«v2rayNG»** и в правом верхнем углу нажимаем на ➕, а затем выбираем **«Импорт из QR-кода»**, выбираем картинку нажав на иконку фото в правом верхнем углу.

**4.** Нажимаем **«справа сверху на три точки»**, а затем **«Проверить задержку профилей»**, после окончания проверки в этом же меню нажмите на **«Сортировать по результатам теста»**. 

**5.** Выбираем нужный вам сервер и затем нажимаем на кнопку ▶️ в правом нижнем углу.

</details>
<details>
<summary>Обновление конфигов в v2rayNG</summary>

**1.** Нажимаем на **«иконку трех полосок»** в **«левом верхнем углу»**.

**2.** Выбираем вкладку **«Группы»**.

**3.** Нажимаем на **«иконку кружка со стрелкой»** в **«правом верхнем углу»**.

</details>

---
<details>

<summary>Гайд для Windows, Linux</summary>

**1.** Скачиваем **«Throne»** — [Windows 10/11](https://github.com/throneproj/Throne/releases/download/1.1.4/Throne-1.1.4-windows64.zip) / [Windows 7/8/8.1](https://github.com/throneproj/Throne/releases/download/1.1.4/Throne-1.1.4-windowslegacy64.zip) / [Linux](https://github.com/throneproj/Throne/releases/download/1.1.4/Throne-1.1.4-linux-amd64.zip)

**2.** Копируем в буфер обмена ссылку из раздела [🗂️ Основные подписки](#-основные-подписки)

**3.** Нажимаем на **«Профили»**, а затем **«Добавить профиль из буфера обмена»**.

**4.** Выделяем все конфиги комбинацией клавиш **«Ctrl + A»**, нажимаем **«Профили»** в верхнем меню, а затем **«Тест задержки (пинга) выбранного профиля»** и дожидаемся окончания теста (во вкладке **«Логи»** появится надпись **«Тест задержек (пинга) завершён!»**)

**5.** Наживаем на кнопку колонки **«Задержка (пинг)»**.

**6.** В верхней части окна программы активируйте опцию **«Режим TUN»**, установив галочку.

**7.** Выбираем один из конфигов с наименьшим **«Задержка (пинг)»**, а затем нажимаем **«ЛКМ»** и **«Запустить»**.

</details>
<details>

<summary>Обновление конфигов в Throne</summary>

**1.** Нажимаем на кнопку **«Настройки»**.

**2.** Выбираем **«Группы»**.

**3.** Нажимаем на кнопку **«Обновить все подписки»**.

</details>

---
<details>
<summary>Гайд для iOS, iPadOS</summary>

**1.** Скачиваем **«Streisand»**  — [Ссылка](https://apps.apple.com/us/app/streisand/id6450534064)

**2.** Копируем в буфер обмена ссылку из раздела [🗂️ Основные подписки](#-основные-подписки)

**3.** Войдите в приложение **«Streisand»** и нажмите кнопку **+**. Затем выберите **«Import from Clipboard(Добавить из буфера)»**

**4.** Зажмите и удерживайте на добавленной подписке и выберете **«Latency(Задержка)»**

**5.** Выберите сервер в наименьшей задержкой и нажмите на кнопку **Включить** вверху
</details>
<details>
<summary>Обновление конфигов в Streisand</summary>

**1.** Зажмите и удерживайте на подписке и выберите **«Update(Обновить)»**

</details>

---
<details>

<summary>Гайд для MacOS</summary>

**1.** Скачиваем **«Hiddify»** — [Ссылка](https://github.com/hiddify/hiddify-app/releases/download/latest/Hiddify-MacOS.dmg)

**2.** Нажимаем **«Новый профиль»**.

**3.** Копируем в буфер обмена ссылку из раздела [🗂️ Основные подписки](#-основные-подписки)

**4.** Нажимаем на кнопку **«Добавить из буфера обмена»**.
   
**5.** Перейдите в **«Настройки»**, измените **«Вариант маршрутизации»** на **«Индонезия»**.

**6.** Нажмите в левом верхнем меню на иконку настроек и выберите **«VPN сервис»**.

**7.** Включаем **«VPN»** нажав на иконку по середине. 

**8.** Для смены сервера включите **«VPN»** и перейдите во вкладку **«Прокси»**.

</details>
<details>

<summary>Обновление конфигов в Hiddify</summary>

**1.** Заходим в приложение **«Hiddify»** и выбираем нужный вам профиль.

**2.** Нажимаем **«слева от названия профиля на иконку обновления»**.

</details>

---

# 📜 Лицензия

Проект распространяется под лицензией GPL-3.0. Полный текст лицензии содержится в файле [`LICENSE`](LICENSE).
