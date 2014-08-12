fs = require 'fs'
lazy = require 'lazy'


class SplunkJSONParser

  @trimLine: (str) ->
    return (str + '').replace /^\s+|\s+$/g, ''


  @stripSlashes: (str) ->
    return (str + '').replace /\\(.?)/g, (s, n1) ->
      switch n1
        when "\\" then return "\\"
        when "0" then return "\u0000"
        when '' then return ''
        else return n1


  @info: (str) ->
    console.log "[sjp] #{str}"


  @error: (str) ->
    console.error "[sjp] #{str}"


  parse: (inputFile, outputFile, callback) ->
    if typeof callback != 'function'
      throw new Error('callback not supplied')

    if !fs.existsSync inputFile
      return callback new Error('Input file does not exist')

    writer = fs.createWriteStream outputFile
    reader = fs.createReadStream inputFile

    if !writer
      return callback new Error('Unable to open file for writing')
    if !reader
      return callback new Error('Unable to open file for reading')

    klass.info 'reading & parsing lines'

    lazy(reader)
      .lines
      .map((line) => @parseLine(line))
      .filter((entry) => Boolean(entry))
      .map((entry) => JSON.stringify(entry))
      .join (strings) =>
        klass.info 'writing output'

        writer.write "[#{strings.join(',')}]", 'utf8', (err) ->
          if err
            return callback err
          writer.end()
          callback null


  parseLine: (line) ->
    # Only parse lines with content
    trimmed = klass.trimLine line
    return null if !trimmed || trimmed.length < 1

    # Don't parse the splunk "lastrow" entry
    try 
      json = JSON.parse line
    catch err
      return null
    return null if json.lastrow
    raw = json?.result?._raw
    return null if !raw

    # Peel off timestamp
    indexOfDateTimeEnd = raw.indexOf(' ')
    return null if indexOfDateTimeEnd == -1
    dateTime = raw.substring 0, indexOfDateTimeEnd
    raw = raw.substring indexOfDateTimeEnd + 1

    # Parsed row
    parsed = {time: dateTime}

    # Take key/values
    splitter = /([^=]+)=([^=]+)(([\s]{1})|$)/g

    while (match = splitter.exec raw) != null
      key = match[1]
      value = match[2]

      # Normalize values
      if value && value.length > 1
        # First strip quotes if present
        if value[0] == '"' && value[-1...] == '"'
          value = value[1...-1]
          
        else if value.length >= 4
          escapedOnce = "\\\""
          escapedTwice = "\\\\\\\""
          if value[0...2] == escapedOnce && value[-2...] == escapedOnce
            value = value[2...-2]

          else if value[0...4] == escapedTwice && value[-4...] == escapedTwice
            value = value[4...-4]

        # Strip and replace escaped quotes
        while (stripped = klass.stripSlashes(value)) != value
          value = stripped
        value = value.replace /\"/g, '"'

        # Try to further pack into native JSON object if was stringified for log
        try 
          asNativeObject = JSON.parse value
          value = asNativeObject if asNativeObject
        catch err
          # Noop: value remains string

      # Assign parsed
      parsed[key] = value

    return parsed


module.exports = klass = SplunkJSONParser
