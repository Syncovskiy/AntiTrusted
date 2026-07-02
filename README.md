# AntiTrusted

<p align="center">
  <b>Минималистичная Windows-утилита для проверки, разблокировки и восстановления ACL у файлов и папок.</b>
</p>

<p align="center">
  <img alt="Windows" src="https://img.shields.io/badge/Windows-10%2B-0078D4?style=flat-square&logo=windows&logoColor=white">
  <img alt="C++17" src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat-square&logo=cplusplus&logoColor=white">
  <img alt="CMake" src="https://img.shields.io/badge/CMake-3.20%2B-064F8C?style=flat-square&logo=cmake&logoColor=white">
</p>

<p align="center">
  <a href="https://github.com/Syncovskiy/AntiTrusted/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/Syncovskiy/AntiTrusted/total?style=flat-square&logo=github"></a>
  <a href="https://github.com/Syncovskiy/AntiTrusted/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/Syncovskiy/AntiTrusted?include_prereleases&style=flat-square"></a>
  <a href="https://github.com/Syncovskiy/AntiTrusted"><img alt="License" src="https://img.shields.io/github/license/Syncovskiy/AntiTrusted?style=flat-square"></a>
</p>

AntiTrusted помогает вернуть доступ к файлам и каталогам, у которых сломаны права доступа или владелец. Основной сценарий - очистка назойливых папок и файлов, заблокированных системой или владельцем `TrustedInstaller`: утилита сначала возвращает вам права, после чего объект можно удалить, переместить или изменить штатными средствами Windows.

Утилита сохраняет исходный security descriptor в резервную копию, назначает текущего пользователя владельцем и выдает ему полный доступ. При необходимости состояние можно восстановить обратно.

> [!CAUTION]
> Команды `unlock` и `restore` изменяют владельца и ACL. Запускайте их только для объектов, которые вы понимаете, и обязательно от имени администратора. Для системных путей (`Windows`, `Program Files`) требуется явный флаг `--force-system`.

## Возможности

- `status` показывает тип объекта, владельца, количество ACE в DACL и наличие backup.
- `unlock` сохраняет backup, назначает текущего пользователя владельцем и добавляет полный доступ.
- `restore` восстанавливает владельца, группу и DACL из сохраненного backup.
- Рекурсивная обработка каталогов через `--recursive`.
- Защита от случайного изменения системных путей.
- Поддержка длинных путей Windows через embedded manifest.

## Когда полезно

- Папка или файл не удаляется из-за владельца `TrustedInstaller`.
- Windows сообщает, что нужны права администратора, но даже elevated Explorer или консоль не помогают.
- Нужно временно получить доступ к каталогу, а затем вернуть исходные ACL из backup.

## Использование

```powershell
AntiTrusted.exe <path>
AntiTrusted.exe status <path> [--recursive] [--backup-dir <dir>]
AntiTrusted.exe unlock <path> [--recursive] [--backup-dir <dir>] [--force-system]
AntiTrusted.exe restore <path> [--recursive] [--backup-dir <dir>] [--force-system]
```

Если передать только путь, откроется интерактивное меню:

```powershell
AntiTrusted.exe "D:\locked-folder"
```

Проверить состояние файла:

```powershell
AntiTrusted.exe status "D:\locked-folder\file.txt"
```

Разблокировать каталог рекурсивно:

```powershell
AntiTrusted.exe unlock "D:\locked-folder" --recursive
```

Восстановить права из backup:

```powershell
AntiTrusted.exe restore "D:\locked-folder" --recursive
```

По умолчанию backup хранится в:

```text
C:\ProgramData\AntiTrusted\backups
```

Путь можно изменить:

```powershell
AntiTrusted.exe unlock "D:\locked-folder" --backup-dir "D:\AntiTrustedBackups"
```

## Сборка

Требования:

- Windows 10 или новее
- Visual Studio 2022 с MSVC
- CMake 3.20+

Сборка Release:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Готовый файл будет расположен здесь:

```text
build\Release\AntiTrusted.exe
```

## Как это работает

Перед изменением прав AntiTrusted сохраняет security descriptor в файл backup, привязанный к нормализованному пути объекта. Backup используется только для того же файла или каталога: при восстановлении утилита проверяет путь и тип объекта.

Для операций изменения прав утилите нужен elevated administrator token и привилегии Windows:

- `SeBackupPrivilege`
- `SeRestorePrivilege`
- `SeTakeOwnershipPrivilege`

## Коды выхода

| Код | Значение |
| --- | --- |
| `0` | Успешно |
| `1` | Некорректные аргументы |
| `2` | Ошибка привилегий или запуск без администратора |
| `3` | Ошибка Windows API |
| `4` | Ошибка backup или restore |

## Release

Готовые сборки публикуются в GitHub Releases. Для проверки целостности используйте SHA256-файл, приложенный к релизу рядом с `AntiTrusted.exe`.
