# Improve Prompt Arg Store Pattern

## Already done

i remove InputSet and rename HostSet to PromptProfile

remove path searcher's cache option, deprecate persist cache

## Changes to be done

Remove SetManager, input arg now managed by promptmanager's base class AMProfileManager(replace legacy HistoryManager)

ProfileManager( need to create and store PromptProfile args

add a class to store pofile, you can split fields

the star-name profile is to store default value, use when

+ client don't have any profile
+ client's profile some attr missing

start-name profile must be ensured, current star-name profile is default value(using when provide value is invalid or missing)

base class AMHistoryManager should be deprecated

remove history change function, change to chang client function

remove ReturnCallback related function, that's not promptmanager's business
