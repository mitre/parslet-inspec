require 'parslet'
require 'parslet/convenience'

class ControlParser < Parslet::Parser
  root :file

  rule :file do
    top_comment >>
        attribute.repeat >>
        control
  end

  rule :top_comment do
    comment.repeat >>
        begin_comment >>
        hyphen.repeat >>
        newline >>
        line_body('-----------------') >>
        hyphen.repeat >>
        newline >>
        end_comment
  end

  rule :attribute do
    str("control").absent? >>
        match('\S').repeat >>
        space.maybe >>
        str('=') >>
        space.maybe >>
        str('attribute(') >>
        newline >>
        line_body(')') >>
        str(')') >>
        newline >>
        newline.maybe
  end

  rule :control do
    str("control") >>
        space.maybe >>
        match('\S').repeat >>
        space >>
        str("do") >>
        newline >>
        title >>
        desc >>
        impact >>
        tag.repeat
  end

  rule :title do
    space.repeat >>
        str('title') >>
        space.maybe >>
        line_body('desc')
  end

  rule :desc do
    space.repeat >>
        str('desc') >>
        space.maybe >>
        line_body('impact 0')
  end

  rule :impact do
    space.repeat >>
        str('impact 0.') >>
        integer >>
        newline
  end

  rule :tag do
    space.repeat >>
        str('tag') >>
        space.maybe >>
        match('\S').repeat >>
        space.maybe >>
        (simple_tag | array | line_body('tag'))
  end

  rule :simple_tag do
    match('\S').repeat >>
        newline
  end

  rule :array do
    str('[') >>
        space.maybe >>
        (newline.absent? >> match('\S').repeat >> space.maybe ).repeat >>
        newline
  end

  rule :comment do
    str('#') >>
        word.repeat >>
        newline
  end

  rule :begin_comment do
    str('=begin') >> newline
  end

  rule :end_comment do
    str('=end') >> newline
  end

  rule :newline do
    str("\r").maybe >> str("\n")
  end

  rule :integer do
    match('[0-9]').repeat(1)
  end

  rule :word do
    space.maybe >> (match('[a-zA-Z0-9/,\.:\'\"]') | hyphen)
  end

  rule :words do
    (space? >> word >> (space | dot | hyphen).maybe).repeat(1) >> (newline >> (word >> space).repeat(1)).maybe
  end

  def line_body(ending)
    (str(ending).absent? >> any).repeat(1)
  end

  def line(ending)
    line_body(ending) >> eol?
  end

  def lines(ending)
    line(ending).as(:line).repeat(1)
  end

  rule :semicolon do
    str(';')
  end

  rule :spaces do
    space.repeat(0)
  end

  rule :space do
    str(' ')
  end

  rule :space? do
    space.maybe
  end

  rule :hyphen do
    str('-')
  end

  rule :dot do
    str('.')
  end
end

class Parser
  def initialize(file_name)
    @file_name = file_name
    @parser = ControlParser.new
    @content = ''
    get_text
    parse
  end

  def parse
    begin
      # puts "############"
      # puts "Parse Data"
      # puts "############"
      parse = puts @parser.parse(@content)
        # parse = p parser.parse(extracted_data)
    rescue Parslet::ParseFailed => error
      puts error.parse_failure_cause.ascii_tree
    end
  end

  def get_text
    File.open(@file_name).each do |line|
      @content << line
    end
  end
end

Parser.new("data/V-72843.rb")