import React, { useEffect, useRef } from 'react';
import clsx from 'clsx';
import './Table.css';

interface Column<T> {
  key: string;
  header: string;
  accessor: (item: T) => React.ReactNode;
  width?: string | number;
  align?: 'left' | 'center' | 'right';
  sortable?: boolean;
  minWidth?: string;
  flex?: number;
}

interface TableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (item: T) => string;
  onRowClick?: (item: T) => void;
  selectedRows?: Set<string>;
  onRowSelect?: (id: string, selected: boolean) => void;
  onSelectAll?: (selected: boolean) => void;
  loading?: boolean;
  emptyMessage?: string;
  className?: string;
  rowClassName?: (item: T, index: number) => string | undefined;
  selectionHeader?: React.ReactNode;
}

export default function Table<T>({
  columns,
  data,
  keyExtractor,
  onRowClick,
  selectedRows,
  onRowSelect,
  onSelectAll,
  loading = false,
  emptyMessage = 'No data available',
  className,
  rowClassName,
  selectionHeader,
}: TableProps<T>) {
  const selectedSet = selectedRows ?? new Set<string>();
  const hasSelection = selectedRows !== undefined && onRowSelect !== undefined;
  const allSelected = hasSelection && data.length > 0 && data.every(item => selectedSet.has(keyExtractor(item)));
  const someSelected = hasSelection && data.some(item => selectedSet.has(keyExtractor(item)));
  const selectAllRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (selectAllRef.current) {
      selectAllRef.current.indeterminate = Boolean(hasSelection && someSelected && !allSelected);
    }
  }, [hasSelection, someSelected, allSelected]);

  // Calculate column styles
  const getColumnStyle = (column: Column<T>, index: number) => {
    const style: React.CSSProperties = {};
    
    if (column.width !== undefined) {
      if (typeof column.width === 'number') {
        style.width = `${column.width}px`;
      } else {
        style.width = column.width;
      }
    } else if (column.flex !== undefined) {
      style.flex = `${column.flex} 1`;
    } else {
      style.flex = '1 1 auto';
    }
    
    if (column.minWidth) {
      style.minWidth = column.minWidth;
    }
    
    return style;
  };

  return (
    <div className={clsx('table-container', className)}>
      {/* Header Row */}
      <div className="table-header-row">
        {hasSelection && (
          <div className="table-cell table-cell-checkbox table-cell-checkbox--header">
            <div className="table-selection-header">
              <input
                type="checkbox"
                className="checkbox"
                checked={allSelected}
                ref={selectAllRef}
                onChange={(e) => onSelectAll?.(e.target.checked)}
              />
            </div>
          </div>
        )}
        {columns.map((column, index) => (
          <div
            key={column.key}
            className="table-cell table-cell-header"
            style={getColumnStyle(column, index)}
          >
            <div className="table-header-content">
              {column.header}
              {column.sortable && (
                <span className="table-sort-icon">
                  <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
                    <path d="M6 1L9 4H3L6 1Z" opacity="0.3" />
                    <path d="M6 11L3 8H9L6 11Z" opacity="0.3" />
                  </svg>
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Body Rows */}
      <div className="table-body">
        {loading ? (
          <div className="table-row table-row-loading">
            <div className="table-cell table-loading">
              <div className="table-loader">
                <span className="loader-spinner" />
                Loading...
              </div>
            </div>
          </div>
        ) : data.length === 0 ? (
          <div className="table-row table-row-empty">
            <div className="table-cell table-empty">
              {emptyMessage}
            </div>
          </div>
        ) : (
          data.map((item, index) => {
            const key = keyExtractor(item);
            const isSelected = hasSelection && selectedSet.has(key);
            const extraRowClass = rowClassName?.(item, index);

            return (
              <div
                key={key}
                className={clsx('table-row', extraRowClass, {
                  'table-row-clickable': onRowClick,
                  'table-row-selected': isSelected,
                })}
                onClick={() => onRowClick?.(item)}
              >
                {hasSelection && (
                  <div className="table-cell table-cell-checkbox">
                    <input
                      type="checkbox"
                      className="checkbox"
                      checked={isSelected}
                      onChange={(e) => {
                        e.stopPropagation();
                        onRowSelect(key, e.target.checked);
                      }}
                    />
                  </div>
                )}
                {columns.map((column, index) => (
                  <div
                    key={column.key}
                    className={clsx('table-cell', `table-align-${column.align || 'left'}`)}
                    style={getColumnStyle(column, index)}
                  >
                    {column.accessor(item)}
                  </div>
                ))}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
